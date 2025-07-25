// server.js - Express backend for invoice manager
const express = require('express');
const cors = require('cors');
const fs = require('fs').promises;
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public')); // Serve static files

// Data files
const CLIENTS_FILE = 'data/clients.json';
const INVOICES_FILE = 'data/invoices.json';
const USERS_FILE = 'data/users.json';

// Ensure data directory exists
async function ensureDataDir() {
  try {
    await fs.mkdir('data', { recursive: true });
    
    // Initialize files if they don't exist
    const files = [
      { path: CLIENTS_FILE, data: [] },
      { path: INVOICES_FILE, data: [] },
      { path: USERS_FILE, data: [{ email: 'tempUser@gmail.com', password: 'tempPass123' }] }
    ];
    
    for (const file of files) {
      try {
        await fs.access(file.path);
      } catch {
        await fs.writeFile(file.path, JSON.stringify(file.data, null, 2));
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
  } catch {
    return [];
  }
}

async function writeJSONFile(filename, data) {
  await fs.writeFile(filename, JSON.stringify(data, null, 2));
}

// Authentication routes
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const users = await readJSONFile(USERS_FILE);
  
  const user = users.find(u => u.email === email && u.password === password);
  if (user) {
    res.json({ success: true, message: 'Login successful' });
  } else {
    res.status(401).json({ success: false, message: 'Invalid credentials' });
  }
});

app.post('/api/register', async (req, res) => {
  const { name, email, password, contactNumber, address } = req.body;
  const users = await readJSONFile(USERS_FILE);
  
  // Check if user already exists
  const existingUser = users.find(u => u.email === email);
  if (existingUser) {
    return res.status(400).json({ success: false, message: 'User already exists' });
  }
  
  users.push({ name, email, password, contactNumber, address });
  await writeJSONFile(USERS_FILE, users);
  
  res.json({ success: true, message: 'Registration successful' });
});

// Client routes
app.get('/api/clients', async (req, res) => {
  const clients = await readJSONFile(CLIENTS_FILE);
  res.json(clients);
});

app.post('/api/clients', async (req, res) => {
  const clients = await readJSONFile(CLIENTS_FILE);
  const newClient = {
    id: clients.length + 1,
    ...req.body,
    invoiceCount: 0,
    totalPaid: 0,
    createdAt: new Date()
  };
  
  clients.push(newClient);
  await writeJSONFile(CLIENTS_FILE, clients);
  
  res.json({ success: true, client: newClient });
});

app.delete('/api/clients/:id', async (req, res) => {
  const clients = await readJSONFile(CLIENTS_FILE);
  const clientId = parseInt(req.params.id);
  
  const updatedClients = clients.filter(c => c.id !== clientId);
  await writeJSONFile(CLIENTS_FILE, updatedClients);
  
  res.json({ success: true });
});

// Invoice routes
app.get('/api/invoices', async (req, res) => {
  const invoices = await readJSONFile(INVOICES_FILE);
  res.json(invoices);
});

app.post('/api/invoices', async (req, res) => {
  const invoices = await readJSONFile(INVOICES_FILE);
  const clients = await readJSONFile(CLIENTS_FILE);
  
  const newInvoice = {
    id: invoices.length + 1,
    ...req.body,
    createdAt: new Date()
  };
  
  invoices.push(newInvoice);
  await writeJSONFile(INVOICES_FILE, invoices);
  
  // Update client stats
  const client = clients.find(c => c.id === newInvoice.clientId);
  if (client) {
    client.invoiceCount++;
    client.totalPaid += newInvoice.total;
    await writeJSONFile(CLIENTS_FILE, clients);
  }
  
  res.json({ success: true, invoice: newInvoice });
});

app.delete('/api/invoices/:id', async (req, res) => {
  const invoices = await readJSONFile(INVOICES_FILE);
  const clients = await readJSONFile(CLIENTS_FILE);
  const invoiceId = parseInt(req.params.id);
  
  const invoice = invoices.find(inv => inv.id === invoiceId);
  if (invoice) {
    // Update client stats
    const client = clients.find(c => c.id === invoice.clientId);
    if (client) {
      client.invoiceCount--;
      client.totalPaid -= invoice.total;
      await writeJSONFile(CLIENTS_FILE, clients);
    }
  }
  
  const updatedInvoices = invoices.filter(inv => inv.id !== invoiceId);
  await writeJSONFile(INVOICES_FILE, updatedInvoices);
  
  res.json({ success: true });
});

// Dashboard stats
app.get('/api/dashboard', async (req, res) => {
  const clients = await readJSONFile(CLIENTS_FILE);
  const invoices = await readJSONFile(INVOICES_FILE);
  
  const stats = {
    totalClients: clients.length,
    totalInvoices: invoices.length,
    totalTax: invoices.reduce((sum, inv) => sum + (inv.taxAmount || 0), 0),
    totalRevenue: invoices.reduce((sum, inv) => sum + (inv.total || 0), 0),
    clientSummary: clients.map(client => ({
      name: client.name,
      email: client.email,
      invoiceCount: client.invoiceCount || 0,
      totalPaid: client.totalPaid || 0
    }))
  };
  
  res.json(stats);
});

// Serve the main HTML file
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
async function startServer() {
  await ensureDataDir();
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Visit: http://localhost:${PORT}`);
  });
}

startServer().catch(console.error);