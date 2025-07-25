// Enhanced server.js with security and production features
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const morgan = require('morgan');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const fs = require('fs').promises;
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-change-in-production';

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net"],
      scriptSrc: ["'self'", "cdn.jsdelivr.net"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100, // limit each IP to 100 requests per windowMs
  message: {
    error: 'Too many requests from this IP, please try again later.'
  }
});

// Auth rate limiting (stricter)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: {
    error: 'Too many authentication attempts, please try again later.'
  }
});

app.use(limiter);
app.use(compression());
app.use(morgan('combined'));

// CORS configuration
const corsOptions = {
  origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
  credentials: true,
};
app.use(cors(corsOptions));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Serve static files
app.use(express.static('public'));

// Data files
const CLIENTS_FILE = path.join(__dirname, 'data/clients.json');
const INVOICES_FILE = path.join(__dirname, 'data/invoices.json');
const USERS_FILE = path.join(__dirname, 'data/users.json');

// Ensure data directory exists
async function ensureDataDir() {
  try {
    await fs.mkdir('data', { recursive: true });
    
    // Initialize files if they don't exist
    const files = [
      { path: CLIENTS_FILE, data: [] },
      { path: INVOICES_FILE, data: [] },
      { 
        path: USERS_FILE, 
        data: [{ 
          id: 1,
          email: 'tempUser@gmail.com', 
          password: await bcrypt.hash('tempPass123', 10),
          name: 'Demo User',
          createdAt: new Date().toISOString()
        }] 
      }
    ];
    
    for (const file of files) {
      try {
        await fs.access(file.path);
      } catch {
        await fs.writeFile(file.path, JSON.stringify(file.data, null, 2));
        console.log(`Created ${file.path}`);
      }
    }
  } catch (error) {
    console.error('Error setting up data directory:', error);
  }
}

// Helper functions
async function readJSONFile(filename) {
  try {
    const data = await fs.readFile(filename, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error(`Error reading ${filename}:`, error);
    return [];
  }
}

async function writeJSONFile(filename, data) {
  try {
    await fs.writeFile(filename, JSON.stringify(data, null, 2));
  } catch (error) {
    console.error(`Error writing ${filename}:`, error);
    throw error;
  }
}

// JWT middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
}

// Validation middleware
const validateClient = [
  body('name').trim().isLength({ min: 2, max: 100 }).escape(),
  body('email').isEmail().normalizeEmail(),
  body('address').trim().isLength({ min: 5, max: 500 }).escape(),
];

const validateInvoice = [
  body('freelancerName').trim().isLength({ min: 2, max: 100 }).escape(),
  body('freelancerEmail').isEmail().normalizeEmail(),
  body('freelancerAddress').trim().isLength({ min: 5, max: 500 }).escape(),
  body('clientId').isInt({ min: 1 }),
  body('taxPercent').isFloat({ min: 0, max: 100 }),
  body('lineItems').isArray({ min: 1 }),
];

// Error handling middleware
function handleValidationErrors(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      error: 'Validation failed',
      details: errors.array()
    });
  }
  next();
}

// Authentication routes
app.post('/api/login', authLimiter, [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 })
], handleValidationErrors, async (req, res) => {
  try {
    const { email, password } = req.body;
    const users = await readJSONFile(USERS_FILE);
    
    const user = users.find(u => u.email === email);
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/register', authLimiter, [
  body('name').trim().isLength({ min: 2, max: 100 }).escape(),
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 }),
  body('contactNumber').isMobilePhone(),
  body('address').trim().isLength({ min: 5, max: 500 }).escape(),
], handleValidationErrors, async (req, res) => {
  try {
    const { name, email, password, contactNumber, address } = req.body;
    const users = await readJSONFile(USERS_FILE);
    
    // Check if user already exists
    const existingUser = users.find(u => u.email === email);
    if (existingUser) {
      return res.status(409).json({ error: 'User already exists' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      id: users.length + 1,
      name,
      email,
      password: hashedPassword,
      contactNumber,
      address,
      createdAt: new Date().toISOString()
    };
    
    users.push(newUser);
    await writeJSONFile(USERS_FILE, users);
    
    const token = jwt.sign(
      { id: newUser.id, email: newUser.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    res.status(201).json({
      success: true,
      token,
      user: {
        id: newUser.id,
        email: newUser.email,
        name: newUser.name
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Protected routes (require authentication)
app.use('/api/clients', authenticateToken);
app.use('/api/invoices', authenticateToken);
app.use('/api/dashboard', authenticateToken);

// Client routes
app.get('/api/clients', async (req, res) => {
  try {
    const clients = await readJSONFile(CLIENTS_FILE);
    res.json(clients);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch clients' });
  }
});

app.post('/api/clients', validateClient, handleValidationErrors, async (req, res) => {
  try {
    const clients = await readJSONFile(CLIENTS_FILE);
    const newClient = {
      id: clients.length + 1,
      ...req.body,
      invoiceCount: 0,
      totalPaid: 0,
      createdAt: new Date().toISOString(),
      userId: req.user.id
    };
    
    clients.push(newClient);
    await writeJSONFile(CLIENTS_FILE, clients);
    
    res.status(201).json({ success: true, client: newClient });
  } catch (error) {
    console.error('Error creating client:', error);
    res.status(500).json({ error: 'Failed to create client' });
  }
});

app.delete('/api/clients/:id', async (req, res) => {
  try {
    const clients = await readJSONFile(CLIENTS_FILE);
    const clientId = parseInt(req.params.id);
    
    const clientExists = clients.some(c => c.id === clientId && c.userId === req.user.id);
    if (!clientExists) {
      return res.status(404).json({ error: 'Client not found' });
    }
    
    const updatedClients = clients.filter(c => c.id !== clientId);
    await writeJSONFile(CLIENTS_FILE, updatedClients);
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete client' });
  }
});

// Invoice routes
app.get('/api/invoices', async (req, res) => {
  try {
    const invoices = await readJSONFile(INVOICES_FILE);
    const userInvoices = invoices.filter(inv => inv.userId === req.user.id);
    res.json(userInvoices);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch invoices' });
  }
});

app.post('/api/invoices', validateInvoice, handleValidationErrors, async (req, res) => {
  try {
    const invoices = await readJSONFile(INVOICES_FILE);
    const clients = await readJSONFile(CLIENTS_FILE);
    
    const newInvoice = {
      id: invoices.length + 1,
      ...req.body,
      createdAt: new Date().toISOString(),
      userId: req.user.id
    };
    
    invoices.push(newInvoice);
    await writeJSONFile(INVOICES_FILE, invoices);
    
    // Update client stats
    const client = clients.find(c => c.id === newInvoice.clientId && c.userId === req.user.id);
    if (client) {
      client.invoiceCount++;
      client.totalPaid += newInvoice.total;
      await writeJSONFile(CLIENTS_FILE, clients);
    }
    
    res.status(201).json({ success: true, invoice: newInvoice });
  } catch (error) {
    console.error('Error creating invoice:', error);
    res.status(500).json({ error: 'Failed to create invoice' });
  }
});

app.delete('/api/invoices/:id', async (req, res) => {
  try {
    const invoices = await readJSONFile(INVOICES_FILE);
    const clients = await readJSONFile(CLIENTS_FILE);
    const invoiceId = parseInt(req.params.id);
    
    const invoice = invoices.find(inv => inv.id === invoiceId && inv.userId === req.user.id);
    if (!invoice) {
      return res.status(404).json({ error: 'Invoice not found' });
    }
    
    // Update client stats
    const client = clients.find(c => c.id === invoice.clientId);
    if (client) {
      client.invoiceCount--;
      client.totalPaid -= invoice.total;
      await writeJSONFile(CLIENTS_FILE, clients);
    }
    
    const updatedInvoices = invoices.filter(inv => inv.id !== invoiceId);
    await writeJSONFile(INVOICES_FILE, updatedInvoices);
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete invoice' });
  }
});

// Dashboard stats
app.get('/api/dashboard', async (req, res) => {
  try {
    const clients = await readJSONFile(CLIENTS_FILE);
    const invoices = await readJSONFile(INVOICES_FILE);
    
    const userClients = clients.filter(c => c.userId === req.user.id);
    const userInvoices = invoices.filter(inv => inv.userId === req.user.id);
    
    const stats = {
      totalClients: userClients.length,
      totalInvoices: userInvoices.length,
      totalTax: userInvoices.reduce((sum, inv) => sum + (inv.taxAmount || 0), 0),
      totalRevenue: userInvoices.reduce((sum, inv) => sum + (inv.total || 0), 0),
      clientSummary: userClients.map(client => ({
        name: client.name,
        email: client.email,
        invoiceCount: client.invoiceCount || 0,
        totalPaid: client.totalPaid || 0
      }))
    };
    
    res.json(stats);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch dashboard data' });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Serve the main HTML file
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// Global error handler
app.use((error, req, res, next) => {
  console.error('Global error handler:', error);
  res.status(500).json({
    error: 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { details: error.message })
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received. Shutting down gracefully...');
  process.exit(0);
});

// Start server
async function startServer() {
  try {
    await ensureDataDir();
    app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`📱 Local: http://localhost:${PORT}`);
      console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

startServer();