# brainwave
npx create-next-app@latest ai-education-platform --typescript
cd ai-education-platform
npm install @prisma/client bcrypt jsonwebtoken axios formidable openai rate-limiter-flexible
npm install --save-dev prisma @types/bcrypt @types/jsonwebtoken @types/formidable
npx prisma init
DATABASE_URL="postgresql://username:password@localhost:5432/ai_education_db?schema=public"
JWT_SECRET="your_very_secret_jwt_key"
OPENAI_API_KEY="your_openai_api_key"
generator client {
  provider = "prisma-client-js"
}

datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

model User {
  id            Int      @id @default(autoincrement())
  email         String   @unique
  password      String
  role          String
  createdAt     DateTime @default(now())
  updatedAt     DateTime @updatedAt
  documents     Document[]
  interactions  Interaction[]
  progress      Progress[]
}

model Document {
  id        Int      @id @default(autoincrement())
  title     String
  content   String
  userId    Int
  user      User     @relation(fields: [userId], references: [id])
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
}

model Interaction {
  id        Int      @id @default(autoincrement())
  query     String
  answer    String
  userId    Int
  user      User     @relation(fields: [userId], references: [id])
  createdAt DateTime @default(now())
}

model Progress {
  id                   Int      @id @default(autoincrement())
  userId               Int
  user                 User     @relation(fields: [userId], references: [id])
  documentId           Int
  completionPercentage Float
  createdAt            DateTime @default(now())
  updatedAt            DateTime @updatedAt
}

model SchemeOfWork {
  id        Int      @id @default(autoincrement())
  title     String
  content   String
  createdBy Int
  createdAt DateTime @default(now())
  updatedAt DateTime @updatedAt
}
npx prisma migrate dev --name init
import { PrismaClient } from '@prisma/client'

let prisma: PrismaClient

if (process.env.NODE_ENV === 'production') {
  prisma = new PrismaClient()
} else {
  if (!global.prisma) {
    global.prisma = new PrismaClient()
  }
  prisma = global.prisma
}

export default prisma
import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'
import { NextApiRequest, NextApiResponse } from 'next'

export const hashPassword = async (password: string): Promise<string> => {
  return bcrypt.hash(password, 10)
}

export const comparePasswords = async (password: string, hashedPassword: string): Promise<boolean> => {
  return bcrypt.compare(password, hashedPassword)
}

export const generateToken = (userId: number, email: string, role: string): string => {
  return jwt.sign({ userId, email, role }, process.env.JWT_SECRET!, { expiresIn: '1d' })
}

export const verifyToken = (token: string): any => {
  return jwt.verify(token, process.env.JWT_SECRET!)
}

export const authenticateUser = (handler: any) => async (req: NextApiRequest, res: NextApiResponse) => {
  const token = req.headers.authorization?.split(' ')[1]
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' })
  }

  try {
    const decoded = verifyToken(token)
    req.user = decoded
    return handler(req, res)
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' })
  }
}

export const authorizeRoles = (...roles: string[]) => (handler: any) => async (req: NextApiRequest, res: NextApiResponse) => {
  if (!roles.includes(req.user.role)) {
    return res.status(403).json({ error: 'Access denied' })
  }
  return handler(req, res)
}
import { Configuration, OpenAIApi } from 'openai'

const configuration = new Configuration({
  apiKey: process.env.OPENAI_API_KEY,
})
const openai = new OpenAIApi(configuration)

export const generateAnswer = async (context: string, query: string): Promise<string> => {
  const completion = await openai.createCompletion({
    model: "text-davinci-002",
    prompt: `Context: ${context}\n\nQuestion: ${query}\n\nAnswer:`,
    max_tokens: 150,
    n: 1,
    stop: null,
    temperature: 0.7,
  })

  return completion.data.choices[0].text.trim()
}

export const generateSchemeOfWork = async (title: string, details: string, topics: string[], objectives: string[]): Promise<string> => {
  const prompt = `Generate a scheme of work for a course titled "${title}". 
  Course details: ${details}
  Topics: ${topics.join(', ')}
  Learning objectives: ${objectives.join(', ')}
  
  Please provide a detailed week-by-week plan including activities and assessments.`

  const completion = await openai.createCompletion({
    model: "text-davinci-002",
    prompt: prompt,
    max_tokens: 1000,
    n: 1,
    stop: null,
    temperature: 0.7,
  })

  return completion.data.choices[0].text.trim()
}
export const validateEmail = (email: string): boolean => {
  const re = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/
  return re.test(email)
}

export const validatePassword = (password: string): boolean => {
  return password.length >= 8
}

export const validateRole = (role: string): boolean => {
  const validRoles = ['learner', 'teacher', 'administrator']
  return validRoles.includes(role)
}
import type { NextApiRequest, NextApiResponse } from 'next'
import prisma from '../../../lib/prisma'
import { hashPassword, generateToken } from '../../../utils/auth'
import { validateEmail, validatePassword, validateRole } from '../../../utils/validation'

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' })
  }

  const { email, password, role } = req.body

  if (!validateEmail(email)) {
    return res.status(400).json({ error: 'Invalid email' })
  }

  if (!validatePassword(password)) {
    return res.status(400).json({ error: 'Password must be at least 8 characters long' })
  }

  if (!validateRole(role)) {
    return res.status(400).json({ error: 'Invalid role' })
  }

  try {
    const existingUser = await prisma.user.findUnique({ where: { email } })
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' })
    }

    const hashedPassword = await hashPassword(password)
    const user = await prisma.user.create({
      data: { email, password: hashedPassword, role },
    })

    const token = generateToken(user.id, user.email, user.role)
    res.status(201).json({ token, user: { id: user.id, email: user.email, role: user.role } })
  } catch (error) {
    console.error('Registration error:', error)
    res.status(500).json({ error: 'Error registering user' })
  }
}
import type { NextApiRequest, NextApiResponse } from 'next'
import prisma from '../../../lib/prisma'
import { comparePasswords, generateToken } from '../../../utils/auth'
import { validateEmail } from '../../../utils/validation'

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' })
  }

  const { email, password } = req.body

  if (!validateEmail(email)) {
    return res.status(400).json({ error: 'Invalid email' })
  }

  try {
    const user = await prisma.user.findUnique({ where: { email } })
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' })
    }

    const isPasswordValid = await comparePasswords(password, user.password)
    if (!isPasswordValid) {
      return res.status(400).json({ error: 'Invalid credentials' })
    }

    const token = generateToken(user.id, user.email, user.role)
    res.status(200).json({ token, user: { id: user.id, email: user.email, role: user.role } })
  } catch (error) {
    console.error('Login error:', error)
    res.status(500).json({ error: 'Error logging in' })
  }
}
import type { NextApiRequest, NextApiResponse } from 'next'
import formidable from 'formidable'
import fs from 'fs'
import prisma from '../../../lib/prisma'
import { authenticateUser } from '../../../utils/auth'

export const config = {
  api: {
    bodyParser: false,
  },
}

const handler = async (req: NextApiRequest, res: NextApiResponse) => {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' })
  }

  const form = new formidable.IncomingForm()
  form.parse(req, async (err, fields, files) => {
    if (err) {
      return res.status(500).json({ error: 'Error parsing form data' })
    }

    const file = files.document as formidable.File
    if (!file) {
      return res.status(400).json({ error: 'No file uploaded' })
    }

    try {
      const content = fs.readFileSync(file.filepath, 'utf8')
      const document = await prisma.document.create({
        data: {
          title: fields.title as string,
          content,
          userId: (req as any).user.userId,
        },
      })

      res.status(200).json({ message: 'Document uploaded successfully', document })
    } catch (error) {
      console.error('Document upload error:', error)
      res.status(500).json({ error: 'Error uploading document' })
    } finally {
      fs.unlinkSync(file.filepath)
    }
  })
}

export default authenticateUser(handler)
import type { NextApiRequest, NextApiResponse } from 'next'
import prisma from '../../lib/prisma'
import { authenticateUser } from '../../utils/auth'
import { generateAnswer } from '../../utils/ai'

const handler = async (req: NextApiRequest, res: NextApiResponse) => {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' })
  }

  const { query } = req.body
  const userId = (req as any).user.userId

  try {
    const documents = await prisma.document.findMany({ where: { userId } })
    const context = documents.map(doc => doc.content).join('\n\n')

    const answer = await generateAnswer(context, query)

    const interaction = await prisma.interaction.create({
      data: { query, answer, userId },
    })

    res.status(200).json({ answer, interactionId: interaction.id })
  } catch (error) {
    console.error('Interaction error:', error)
    res.status(500).json({ error: 'Error processing interaction' })
  }
}

export default authenticateUser(handler)
import type { NextApiRequest, NextApiResponse } from 'next'
import prisma from '../../../lib/prisma'
import { authenticateUser, authorizeRoles } from '../../../utils/auth'
import { generateSchemeOfWork } from '../../../utils/ai'

const handler = async (req: NextApiRequest, res: NextApiResponse) => {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' })
  }

  const { title, details, topics, objectives } = req.body
  const userId = (req as any).user.userId

  try {
    const content = await generateSchemeOfWork(title, details, topics, objectives)

    const schemeOfWork = await prisma.schemeOfWork.create({
      data: { title, content, createdBy: userId },
    })

    res.status(200).json({ message: 'Scheme of work generated successfully', schemeOfWork })
  } catch (error) {
    console.error('Scheme of work generation error:', error)
    res.status(500).json({ error: 'Error generating scheme of work' })
  }
}

export default authenticateUser(authorizeRoles('teacher', 'administrator')(handler))
import React from 'react'
import Link from 'next/link'
import { useRouter } from 'next/router'

interface LayoutProps {
  children: React.ReactNode
}

const Layout: React.FC<LayoutProps> = ({ children }) => {
  const router = useRouter()

  const handleLogout = () => {
    localStorage.removeItem('token')
    router.push('/login')
  }

  return (
    <div className="min-h-screen bg-gray-100">
      <nav className="bg-white shadow-lg">
        <div className="max-w-7xl mx-auto px-4">
          <div className="flex justify-between">
            <div className="flex space-x-7">
              <Link href="/" className="flex items-center py-4 px-2">
                <span className="font-semibold text-gray-500 text-lg">AI Education Platform</span>
              </Link>
            </div>
            <div className="flex items-center space-x-3">
              <Link href="/dashboard" className="py-2 px-2 font-medium text-gray-500 rounded hover:bg-green-500 hover:text-white transition duration-300">Dashboard</Link>
              <Link href="/profile" className="py-2 px-2 font-medium text-gray-500 rounded hover:bg-green-500 hover:text-white transition duration-300">Profile</Link>
              <button onClick={handleLogout} className="py-2 px-2 font-medium text-white bg-red-500 rounded hover:bg-red-400 transition duration-300">Logout</button>
            </div>
          </div>
        </div>
      </nav>
      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        {children}
      </main>
    </div>
  )
}

export default Layout
import React, { useState } from 'react'
import { useRouter } from 'next/router'
import axios from 'axios'

const LoginForm: React.FC = () => {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const router = useRouter()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')

    try {
      const response = await axios.post('/api/auth/login', { email, password })
      localStorage.setItem('token', response.data.token)
      router.push('/dashboard')
    } catch (error: any) {
      setError(error.response?.data?.error || 'An error occurred during login')
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label htmlFor="email" className="block text-sm font-medium text-gray-700">Email</label>
        <input
          type="email"
          id="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
          required
        />
      </div>
      <div>
        <label htmlFor="password" className="block text-sm font-medium text-gray-700">Password</label>
        <input
          type="password"
          id="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
          required
        />
      </div>
      {error && <p className="text-red-500 text-sm">{error}</p>}
      <button type="submit" className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500">
        Log In
      </button>
    </form>
  )
}

export default LoginForm
import React, { useState } from 'react'
import { useRouter } from 'next/router'
import axios from 'axios'

const RegisterForm: React.FC = () => {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState('learner')
  const [error, setError] = useState('')
  const router = useRouter()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')

    try {
      const response = await axios.post('/api/auth/register', { email, password, role })
      localStorage.setItem('token', response.data.token)
      router.push('/dashboard')
    } catch (error: any) {
      setError(error.response?.data?.error || 'An error occurred during registration')
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label htmlFor="email" className="block text-sm font-medium text-gray-700">Email</label>
        <input
          type="email"
          id="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
          required
        />
      </div>
      <div>
        <label htmlFor="password" className="block text-sm font-medium text-gray-700">Password</label>
        <input
          type="password"
          id="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
          required
        />
      </div>
      <div>
        <label htmlFor="role" className="block text-sm font-medium text-gray-700">Role</label>
        <select
          id="role"
          value={role}
          onChange={(e) => setRole(e.target.value)}
          className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
        >
          <option value="learner">Learner</option>
          <option value="teacher">Teacher</option>
          <option value="administrator">Administrator</option>
        </select>
      </div>
      {error && <p className="text-red-500 text-sm">{error}</p>}
      <button type="submit" className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500">
        Register
      </button>
    </form>
  )
}

export default RegisterForm
import React, { useState } from 'react'
import axios from 'axios'

const DocumentUploader: React.FC = () => {
  const [file, setFile] = useState<File | null>(null)
  const [title, setTitle] = useState('')
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setSuccess('')

    if (!file) {
      setError('Please select a file to upload')
      return
    }

    const formData = new FormData()
    formData.append('document', file)
    formData.append('title', title)

    try {
      const response = await axios.post('/api/documents/upload', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
      })
      setSuccess('Document uploaded successfully')
      setFile(null)
      setTitle('')
    } catch (error: any) {
      setError(error.response?.data?.error || 'Error uploading document')
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div>
        <label htmlFor="title" className="block text-sm font-medium text-gray-700">Document Title</label>
        <input
          type="text"
          id="title"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
          required
        />
      </div>
      <div>
        <label htmlFor="document" className="block text-sm font-medium text-gray-700">Document</label>
        <input
          type="file"
          id="document"
          onChange={(e) => e.target.files && setFile(e.target.files[0])}
          className="mt-1 block w-full"
          required
        />
      </div>
      {error && <p className="text-red-500 text-sm">{error}</p>}
      {success && <p className="text-green-500 text-sm">{success}</p>}
      <button type="submit" className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500">
        Upload Document
      </button>
    </form>
  )
}

export default DocumentUploader
import React, { useState } from 'react'
import axios from 'axios'

const LearnerInteraction: React.FC = () => {
  const [query, setQuery] = useState('')
  const [answer, setAnswer] = useState('')
  const [error, setError] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setAnswer('')

    try {
      const response = await axios.post('/api/interact', { query }, {
        headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
      })
      setAnswer(response.data.answer)
    } catch (error: any) {
      setError(error.response?.data?.error || 'Error processing your question')
    }
  }

  return (
    <div className="space-y-4">
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="query" className="block text-sm font-medium text-gray-700">Ask a question</label>
          <input
            type="text"
            id="query"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
            required
          />
        </div>
        <button type="submit" className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500">
          Ask
        </button>
      </form>
      {error && <p className="text-red-500 text-sm">{error}</p>}
      {answer && (
        <div className="mt-4">
          <h3 className="text-lg font-medium text-gray-900">Answer:</h3>
          <p className="mt-2 text-sm text-gray-500">{answer}</p>
        </div>
      )}
    </div>
  )
}

export default LearnerInteraction
import React, { useState } from 'react'
import axios from 'axios'

const SchemeOfWorkGenerator: React.FC = () => {
  const [title, setTitle] = useState('')
  const [details, setDetails] = useState('')
  const [topics, setTopics] = useState('')
  const [objectives, setObjectives] = useState('')
  const [schemeOfWork, setSchemeOfWork] = useState('')
  const [error, setError] = useState('')

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setSchemeOfWork('')

    try {
      const response = await axios.post('/api/schemeofwork/generate', {
        title,
        details,
        topics: topics.split(',').map(t => t.trim()),
        objectives: objectives.split(',').map(o => o.trim()),
      }, {
        headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
      })
      setSchemeOfWork(response.data.schemeOfWork.content)
    } catch (error: any) {
      setError(error.response?.data?.error || 'Error generating scheme of work')
    }
  }

  return (
    <div className="space-y-4">
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="title" className="block text-sm font-medium text-gray-700">Course Title</label>
          <input
            type="text"
            id="title"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
            required
          />
        </div>
        <div>
          <label htmlFor="details" className="block text-sm font-medium text-gray-700">Course Details</label>
          <textarea
            id="details"
            value={details}
            onChange={(e) => setDetails(e.target.value)}
            className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
            required
          />
        </div>
        <div>
          <label htmlFor="topics" className="block text-sm font-medium text-gray-700">Topics (comma-separated)</label>
          <input
            type="text"
            id="topics"
            value={topics}
            onChange={(e) => setTopics(e.target.value)}
            className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
            required
          />
        </div>
        <div>
          <label htmlFor="objectives" className="block text-sm font-medium text-gray-700">Learning Objectives (comma-separated)</label>
          <input
            type="text"
            id="objectives"
            value={objectives}
            onChange={(e) => setObjectives(e.target.value)}
            className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
            required
          />
        </div>
        <button type="submit" className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500">
          Generate Scheme of Work
        </button>
      </form>
      {error && <p className="text-red-500 text-sm">{error}</p>}
      {schemeOfWork && (
        <div className="mt-4">
          <h3 className="text-lg font-medium text-gray-900">Generated Scheme of Work:</h3>
          <pre className="mt-2 whitespace-pre-wrap text-sm text-gray-500">{schemeOfWork}</pre>
        </div>
      )}
    </div>
  )
}

export default SchemeOfWorkGenerator
import type { NextPage } from 'next'
import Head from 'next/head'
import Link from 'next/link'
import Layout from '../components/Layout'

const Home: NextPage = () => {
  return (
    <Layout>
      <Head>
        <title>AI Education Platform</title>
        <meta name="description" content="AI-powered education platform" />
        <link rel="icon" href="/favicon.ico" />
      </Head>

      <div className="text-center">
        <h1 className="text-4xl font-bold mb-4">Welcome to AI Education Platform</h1>
        <p className="text-xl mb-8">Empower your learning with AI-assisted education</p>
        <div className="space-x-4">
          <Link href="/login" className="inline-block bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600">
            Login
          </Link>
          <Link href="/register" className="inline-block bg-green-500 text-white px-4 py-2 rounded hover:bg-green-600">
            Register
          </Link>
        </div>
      </div>
    </Layout>
  )
}

export default Home
import type { NextPage } from 'next'
import Head from 'next/head'
import Layout from '../components/Layout'
import LoginForm from '../components/LoginForm'

const Login: NextPage = () => {
  return (
    <Layout>
      <Head>
        <title>Login - AI Education Platform</title>
        <meta name="description" content="Login to AI Education Platform" />
        <link rel="icon" href="/favicon.ico" />
      </Head>

      <div className="max-w-md mx-auto">
        <h1 className="text-3xl font-bold mb-4">Login</h1>
        <LoginForm />
      </div>
    </Layout>
  )
}

export default Login
import type { NextPage } from 'next'
import Head from 'next/head'
import Layout from '../components/Layout'
import RegisterForm from '../components/RegisterForm'

const Register: NextPage = () => {
  return (
    <Layout>
      <Head>
        <title>Register - AI Education Platform</title>
        <meta name="description" content="Register for AI Education Platform" />
        <link rel="icon" href="/favicon.ico" />
      </Head>

      <div className="max-w-md mx-auto">
        <h1 className="text-3xl font-bold mb-4">Register</h1>
        <RegisterForm />
      </div>
    </Layout>
  )
}

export default Register
import type { NextPage } from 'next'
import { useEffect, useState } from 'react'
import Head from 'next/head'
import { useRouter } from 'next/router'
import Layout from '../components/Layout'
import DocumentUploader from '../components/DocumentUploader'
import LearnerInteraction from '../components/LearnerInteraction'
import SchemeOfWorkGenerator from '../components/SchemeOfWorkGenerator'

const Dashboard: NextPage = () => {
  const [userRole, setUserRole] = useState<string | null>(null)
  const router = useRouter()

  useEffect(() => {
    const token = localStorage.getItem('token')
    if (!token) {
      router.push('/login')
    } else {
      // Decode the token to get the user role
      const payload = JSON.parse(atob(token.split('.')[1]))
      setUserRole(payload.role)
    }
  }, [router])

  if (!userRole) {
    return <div>Loading...</div>
  }

  return (
    <Layout>
      <Head>
        <title>Dashboard - AI Education Platform</title>
        <meta name="description" content="AI Education Platform Dashboard" />
        <link rel="icon" href="/favicon.ico" />
      </Head>

      <h1 className="text-3xl font-bold mb-4">Dashboard</h1>
      <div className="space-y-8">
        <DocumentUploader />
        <LearnerInteraction />
        {(userRole === 'teacher' || userRole === 'administrator') && (
          <SchemeOfWorkGenerator />
        )}
      </div>
    </Layout>
  )
}

export default Dashboard
import type { NextPage } from 'next'
import { useEffect, useState } from 'react'
import Head from 'next/head'
import { useRouter } from 'next/router'
import axios from 'axios'
import Layout from '../components/Layout'

const Profile: NextPage = () => {
  const [user, setUser] = useState<any>(null)
  const [email, setEmail] = useState('')
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const router = useRouter()

  useEffect(() => {
    const token = localStorage.getItem('token')
    if (!token) {
      router.push('/login')
    } else {
      // Decode the token to get the user info
      const payload = JSON.parse(atob(token.split('.')[1]))
      setUser(payload)
      setEmail(payload.email)
    }
  }, [router])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setSuccess('')

    try {
      const response = await axios.put(`/api/users/${user.userId}`, { email }, {
        headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
      })
      setSuccess('Profile updated successfully')
    } catch (error: any) {
      setError(error.response?.data?.error || 'Error updating profile')
    }
  }

  if (!user) {
    return <div>Loading...</div>
  }

  return (
    <Layout>
      <Head>
        <title>Profile - AI Education Platform</title>
        <meta name="description" content="User Profile - AI Education Platform" />
        <link rel="icon" href="/favicon.ico" />
      </Head>

      <h1 className="text-3xl font-bold mb-4">Profile</h1>
      <form onSubmit={handleSubmit} className="space-y-4 max-w-md">
        <div>
          <label htmlFor="email" className="block text-sm font-medium text-gray-700">Email</label>
          <input
            type="email"
            id="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="mt-1 block w-full border border-gray-300 rounded-md shadow-sm py-2 px-3 focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
            required
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700">Role</label>
          <p className="mt-1 text-sm text-gray-500">{user.role}</p>
        </div>
        {error && <p className="text-red-500 text-sm">{error}</p>}
        {success && <p className="text-green-500 text-sm">{success}</p>}
        <button type="submit" className="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500">
          Update Profile
        </button>
      </form>
    </Layout>
  )
}

export default Profile
import '../styles/globals.css'
import type { AppProps } from 'next/app'

function MyApp({ Component, pageProps }: AppProps) {
  return <Component {...pageProps} />
}

export default MyApp
/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  swcMinify: true,
}

module.exports = nextConfig
