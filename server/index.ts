import http from 'http'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)
const ROOT_DIR = path.join(__dirname, '..')
const PORT = process.env.DEPLOY_RUN_PORT || 5000

interface Issue {
  line: number
  severity: 'error' | 'warning' | 'info'
  category: 'security' | 'performance' | 'best-practice' | 'syntax'
  message: string
  suggestion: string
}

const JAVA_RULES = [
  { pattern: /SELECT\s+\*\s+FROM.*WHERE.*\+\s*\w+/gi, severity: 'error' as const, category: 'security' as const, message: 'SQL 注入风险：字符串拼接方式构建 SQL 查询', suggestion: '使用 PreparedStatement 的参数化查询。' },
  { pattern: /Statement\s+\w+\s*=\s*\w+\.createStatement\(\)/gi, severity: 'warning' as const, category: 'performance' as const, message: '使用 Statement 而非 PreparedStatement', suggestion: '推荐使用 PreparedStatement。' },
  { pattern: /\.executeQuery\(.*\+\s*\w+/g, severity: 'error' as const, category: 'security' as const, message: '可能的 SQL 注入：动态拼接变量', suggestion: '使用参数化查询。' },
  { pattern: /new\s+\w+\(rs\.getString\(/gi, severity: 'warning' as const, category: 'best-practice' as const, message: '空指针风险：可能返回 null', suggestion: '检查是否为 null 或使用 Optional。' },
  { pattern: /Connection\s+\w+\s*=.*\.getConnection\(\)/gi, severity: 'warning' as const, category: 'performance' as const, message: '资源泄漏：连接可能未关闭', suggestion: '使用 try-with-resources。' },
  { pattern: /System\.out\.print/g, severity: 'info' as const, category: 'best-practice' as const, message: '日志规范：使用 System.out', suggestion: '使用 SLF4J 日志框架。' },
  { pattern: /catch\s*\(\s*Exception\s+\w+\s*\)\s*\{\s*\}/gi, severity: 'warning' as const, category: 'best-practice' as const, message: '异常处理：空异常块', suggestion: '至少记录异常日志。' },
  { pattern: /ArrayList\s*<.*>\s*\w+\s*=\s*new\s+ArrayList/gi, severity: 'info' as const, category: 'best-practice' as const, message: '集合类型建议', suggestion: '使用 List<...> list = new ArrayList<...>()。' },
]

const MYSQL_RULES = [
  { pattern: /SELECT\s+\*/gi, severity: 'warning' as const, category: 'performance' as const, message: 'SELECT * 可能导致性能问题', suggestion: '明确指定需要的列名。' },
  { pattern: /FROM\s+\w+\s*,\s*\w+/gi, severity: 'warning' as const, category: 'best-practice' as const, message: '隐式连接', suggestion: '使用显式 JOIN。' },
  { pattern: /WHERE.*!=\s*\w+|WHERE.*<>\s*\w+/gi, severity: 'warning' as const, category: 'performance' as const, message: '不等于查询可能无法使用索引', suggestion: '确保该列有适当的索引。' },
  { pattern: /LIMIT\s+10000|LIMIT\s+9999/g, severity: 'warning' as const, category: 'performance' as const, message: '大偏移量分页', suggestion: '使用游标分页替代。' },
  { pattern: /password\s+FROM|passwd\s+FROM|pwd\s+FROM/gi, severity: 'error' as const, category: 'security' as const, message: '安全风险：直接查询密码', suggestion: '不要返回密码字段。' },
  { pattern: /INSERT\s+INTO.*VALUES\s*\(/gi, severity: 'info' as const, category: 'best-practice' as const, message: 'INSERT 未指定列名', suggestion: '明确指定插入的列名。' },
  { pattern: /DROP\s+TABLE(?!\s+IF\s+EXISTS)/gi, severity: 'warning' as const, category: 'best-practice' as const, message: 'DROP TABLE 未检查', suggestion: '使用 DROP TABLE IF EXISTS。' },
]

function analyzeCode(code: string, language: 'java' | 'mysql'): Issue[] {
  const rules = language === 'java' ? JAVA_RULES : MYSQL_RULES
  const issues: Issue[] = []
  rules.forEach((rule) => {
    const matches = code.match(rule.pattern)
    if (matches) {
      matches.forEach((match) => {
        let lineNum = 1
        let remainingCode = code
        let matchIndex = remainingCode.indexOf(match)
        while (matchIndex === -1 && remainingCode.length > 0) {
          const lineBreakIndex = remainingCode.indexOf('\n')
          if (lineBreakIndex === -1) break
          lineNum++
          remainingCode = remainingCode.substring(lineBreakIndex + 1)
          matchIndex = remainingCode.indexOf(match)
        }
        if (matchIndex !== -1) {
          const beforeMatch = remainingCode.substring(0, matchIndex)
          lineNum += (beforeMatch.match(/\n/g) || []).length
          if (!issues.some((i) => i.line === lineNum && i.message === rule.message)) {
            issues.push({ line: lineNum, severity: rule.severity, category: rule.category, message: rule.message, suggestion: rule.suggestion })
          }
        }
      })
    }
  })
  return issues.sort((a, b) => a.line - b.line)
}

const server = http.createServer((req, res) => {
  const url = req.url || '/'
  
  // API route
  if (req.method === 'POST' && url === '/api/code-review') {
    let body = ''
    req.on('data', chunk => { body += chunk })
    req.on('end', () => {
      try {
        const { code, language } = JSON.parse(body)
        if (!code || !language) {
          res.writeHead(400, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ error: 'Missing required fields' }))
          return
        }
        if (!['java', 'mysql'].includes(language)) {
          res.writeHead(400, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({ error: 'Invalid language' }))
          return
        }
        setTimeout(() => {
          const issues = analyzeCode(code, language)
          res.writeHead(200, { 'Content-Type': 'application/json' })
          res.end(JSON.stringify({
            issues,
            summary: { total: issues.length, errors: issues.filter((i) => i.severity === 'error').length, warnings: issues.filter((i) => i.severity === 'warning').length, suggestions: issues.filter((i) => i.severity === 'info').length },
            timestamp: new Date().toISOString(),
          }))
        }, 800 + Math.random() * 800)
      } catch {
        res.writeHead(500, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ error: 'Internal server error' }))
      }
    })
    return
  }

  // Static files
  let filePath = url === '/' ? '/index.html' : url
  filePath = path.join(ROOT_DIR, filePath)
  
  const ext = path.extname(filePath)
  const contentTypes: Record<string, string> = {
    '.html': 'text/html',
    '.js': 'application/javascript',
    '.css': 'text/css',
    '.json': 'application/json',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.ico': 'image/x-icon',
  }
  
  fs.readFile(filePath, (err, data) => {
    if (err) {
      // Fallback to index.html
      fs.readFile(path.join(ROOT_DIR, 'index.html'), (err2, data2) => {
        if (err2) {
          res.writeHead(404)
          res.end('Not Found')
        } else {
          res.writeHead(200, { 'Content-Type': 'text/html' })
          res.end(data2)
        }
      })
    } else {
      res.writeHead(200, { 'Content-Type': contentTypes[ext] || 'text/plain' })
      res.end(data)
    }
  })
})

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})
