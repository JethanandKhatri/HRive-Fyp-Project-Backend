import 'dotenv/config'
import express from 'express'
import cors from 'cors'
import bcrypt from 'bcrypt'
import pkg from 'pg'
import { createClient } from '@supabase/supabase-js'

const { Pool } = pkg

const app = express()
app.use(cors())
app.use(express.json())

const {
  DATABASE_URL = 'postgres://postgres:postgres@localhost:5432/hrive',
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  PORT = 4000,
} = process.env

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: DATABASE_URL?.includes('supabase.co') ? { rejectUnauthorized: false } : undefined,
})

const supabase =
  SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY
    ? createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
    : null

const navByPortal = {
  hr: ['HR Dashboard', 'Holidays', 'Events', 'Activities', 'HR Social', 'Employees', 'Accounts', 'Payroll'],
  admin: ['Admin Dashboard', 'Systems', 'Policies', 'Audit', 'Billing', 'Security'],
  manager: ['Manager Dashboard', 'Projects', 'Squads', 'Risks', 'Approvals'],
  employee: ['My Dashboard', 'Tasks', 'Approvals', 'Payslips', 'Time Off', 'Growth'],
}

const metrics = {
  admin: [
    { label: 'Systems Online', value: '16' },
    { label: 'Teams', value: '42' },
    { label: 'Policies', value: '18' },
    { label: 'Avg. Response', value: '2.4h' },
  ],
  hr: [
    { label: 'New Employee', value: '22' },
    { label: 'Total Employee', value: '425' },
    { label: 'Total Salary', value: '$2.8M' },
    { label: 'Avg. Salary', value: '$1,250' },
  ],
  manager: [
    { label: 'Projects Active', value: '12' },
    { label: 'Squads', value: '8' },
    { label: 'Risks', value: '3' },
    { label: 'Hiring Needs', value: '4' },
  ],
  employee: [
    { label: 'Open Tasks', value: '9' },
    { label: 'Approvals Pending', value: '3' },
    { label: 'Trainings', value: '2' },
    { label: 'Leave Balance', value: '14d' },
  ],
}

const lists = {
  holidays: ['New Year', 'Spring Break', 'Independence Day'],
  events: ['Town Hall', 'Tech Talk', 'Wellness Friday'],
  activities: ['Hackathon', 'Volunteer Day', 'Workshop'],
  social: ['Coffee Chat', 'Team Lunch', 'Offsite'],
  employees: ['Jessica Doe', 'Alex Kim', 'Samir Khan'],
  accounts: ['Payroll', 'Benefits', 'Reimbursements'],
  payroll: ['Cycle Jan', 'Cycle Feb', 'Cycle Mar'],
  systems: ['HRIS', 'OKR', 'Payroll'],
  policies: ['Leave Policy', 'Expense Policy', 'Security Policy'],
  audit: ['Q1 Audit', 'Q2 Audit'],
  billing: ['Invoice #1021', 'Invoice #1022'],
  security: ['MFA Rollout', 'SSO Integration'],
  projects: ['Apollo', 'Zephyr', 'Horizon'],
  squads: ['Falcon Squad', 'Nova Squad'],
  risks: ['Resource Gap', 'Scope Creep'],
  approvals: ['Purchase Request', 'Leave Request'],
  tasks: ['Submit status', 'Update Jira', 'Review PRs'],
  payslips: ['Jan Payslip', 'Feb Payslip'],
  timeoff: ['Remaining: 14 days'],
  growth: ['Learning Budget', 'Career Path'],
}

async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK (role IN ('admin','hr','manager','employee'))
    )
  `)

  const seedUsers = [
    { email: 'admin@hrive.com', password: 'admin123', role: 'admin' },
    { email: 'hr@hrive.com', password: 'hr12345', role: 'hr' },
    { email: 'manager@hrive.com', password: 'manager123', role: 'manager' },
    { email: 'employee@hrive.com', password: 'employee123', role: 'employee' },
  ]

  for (const user of seedUsers) {
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [user.email])
    if (existing.rows.length === 0) {
      const hash = await bcrypt.hash(user.password, 10)
      await pool.query('INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3)', [
        user.email,
        hash,
        user.role,
      ])
    }
  }
}

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body || {}
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' })
  try {
    let user = null

    if (supabase) {
      const { data, error } = await supabase
        .from('users')
        .select('id, email, password_hash, role')
        .eq('email', email)
        .maybeSingle()

      if (error) return res.status(500).json({ error: 'DB error', detail: error.message })
      user = data
    } else {
      const result = await pool.query('SELECT id, email, password_hash, role FROM users WHERE email = $1', [email])
      user = result.rows[0]
    }

    if (!user) return res.status(401).json({ error: 'Invalid credentials' })
    const ok = await bcrypt.compare(password, user.password_hash)
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' })
    res.json({ role: user.role, email: user.email })
  } catch (err) {
    res.status(500).json({ error: 'Unexpected error', detail: err.message })
  }
})

app.post('/api/auth/signup', async (req, res) => {
  const { email, password, role = 'employee' } = req.body || {}
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' })
  if (!['admin', 'hr', 'manager', 'employee'].includes(role)) return res.status(400).json({ error: 'Invalid role' })
  try {
    if (supabase) {
      const { data: existing, error: existingErr } = await supabase
        .from('users')
        .select('id')
        .eq('email', email)
        .maybeSingle()
      if (existingErr) return res.status(500).json({ error: 'DB error', detail: existingErr.message })
      if (existing) return res.status(409).json({ error: 'Email already exists' })

      const hash = await bcrypt.hash(password, 10)
      const { data: inserted, error: insertErr } = await supabase
        .from('users')
        .insert([{ email, password_hash: hash, role }])
        .select('id, email, role')
        .single()

      if (insertErr) return res.status(500).json({ error: 'DB error', detail: insertErr.message })
      return res.status(201).json({ role: inserted.role, email: inserted.email })
    } else {
      const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email])
      if (existing.rows.length) return res.status(409).json({ error: 'Email already exists' })
      const hash = await bcrypt.hash(password, 10)
      const inserted = await pool.query(
        'INSERT INTO users (email, password_hash, role) VALUES ($1, $2, $3) RETURNING id, email, role',
        [email, hash, role],
      )
      const user = inserted.rows[0]
      res.status(201).json({ role: user.role, email: user.email })
    }
  } catch (err) {
    res.status(500).json({ error: 'Unexpected error', detail: err.message })
  }
})

app.get('/api/portal/:role/summary', (req, res) => {
  const { role } = req.params
  if (!metrics[role]) return res.status(404).json({ error: 'Unknown role' })
  res.json({
    role,
    nav: navByPortal[role] ?? [],
    metrics: metrics[role],
  })
})

app.get('/api/portal/:portalId/:section', (req, res) => {
  const { section } = req.params
  const data = lists[section] ?? []
  res.json({ section, items: data })
})

app.get('/api/health', (req, res) => res.json({ ok: true }))

ensureSchema()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`API running on http://localhost:${PORT}`)
    })
  })
  .catch((err) => {
    console.error('Failed to start server', err)
    process.exit(1)
  })
