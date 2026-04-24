import express, { Request, Response } from 'express'
import path from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const app = express()
const PORT = process.env.DEPLOY_RUN_PORT || 5000

app.use(express.json())

interface Issue {
  line: number
  severity: 'error' | 'warning' | 'info'
  category: 'security' | 'performance' | 'best-practice' | 'syntax'
  message: string
  suggestion: string
}

const JAVA_RULES = [
  {
    pattern: /SELECT\s+\*\s+FROM.*WHERE.*\+\s*\w+/gi,
    severity: 'error' as const,
    category: 'security' as const,
    message: 'SQL 注入风险：字符串拼接方式构建 SQL 查询',
    suggestion: '使用 PreparedStatement 的参数化查询，或使用 ORM 框架的参数绑定功能。',
  },
  {
    pattern: /Statement\s+\w+\s*=\s*\w+\.createStatement\(\)/gi,
    severity: 'warning' as const,
    category: 'performance' as const,
    message: '使用 Statement 而非 PreparedStatement',
    suggestion: '推荐使用 PreparedStatement，它具有性能优势和防止 SQL 注入。',
  },
  {
    pattern: /\.executeQuery\(.*\+\s*\w+/g,
    severity: 'error' as const,
    category: 'security' as const,
    message: '可能的 SQL 注入：动态拼接变量到 SQL 语句',
    suggestion: '使用参数化查询代替字符串拼接。',
  },
  {
    pattern: /new\s+\w+\(rs\.getString\(/gi,
    severity: 'warning' as const,
    category: 'best-practice' as const,
    message: '空指针风险：ResultSet 的 getString() 可能返回 null',
    suggestion: '在使用 rs.getString() 返回值之前检查是否为 null，或使用 Optional 处理。',
  },
  {
    pattern: /Connection\s+\w+\s*=.*\.getConnection\(\)/gi,
    severity: 'warning' as const,
    category: 'performance' as const,
    message: '资源泄漏风险：数据库连接可能未正确关闭',
    suggestion: '使用 try-with-resources 语句确保 Connection、Statement、ResultSet 等资源正确关闭。',
  },
  {
    pattern: /System\.out\.print/g,
    severity: 'info' as const,
    category: 'best-practice' as const,
    message: '日志规范：不应使用 System.out 进行日志输出',
    suggestion: '使用专业的日志框架（SLF4J + Logback/Log4j2）替代 System.out。',
  },
  {
    pattern: /catch\s*\(\s*Exception\s+\w+\s*\)\s*\{\s*\}/gi,
    severity: 'warning' as const,
    category: 'best-practice' as const,
    message: '异常处理：捕获空异常块',
    suggestion: '至少记录异常日志，或根据业务需求进行适当处理。',
  },
  {
    pattern: /ArrayList\s*<.*>\s*\w+\s*=\s*new\s+ArrayList/gi,
    severity: 'info' as const,
    category: 'best-practice' as const,
    message: '集合类型建议：使用接口类型声明变量',
    suggestion: '推荐使用 List<...> list = new ArrayList<...>() 方式声明。',
  },
]

const MYSQL_RULES = [
  {
    pattern: /SELECT\s+\*/gi,
    severity: 'warning' as const,
    category: 'performance' as const,
    message: '使用 SELECT * 可能导致性能问题',
    suggestion: '明确指定需要的列名，避免不必要的数据传输和索引失效。',
  },
  {
    pattern: /FROM\s+\w+\s*,\s*\w+/gi,
    severity: 'warning' as const,
    category: 'best-practice' as const,
    message: '隐式连接：使用逗号分隔表',
    suggestion: '使用显式 JOIN 语法，使查询意图更清晰。',
  },
  {
    pattern: /WHERE.*!=\s*\w+|WHERE.*<>\s*\w+/gi,
    severity: 'warning' as const,
    category: 'performance' as const,
    message: '不等于查询可能无法使用索引',
    suggestion: '考虑是否可以用其他方式表达逻辑，或确保该列有适当的索引。',
  },
  {
    pattern: /LIMIT\s+10000|LIMIT\s+9999/g,
    severity: 'warning' as const,
    category: 'performance' as const,
    message: '大偏移量分页可能导致性能问题',
    suggestion: '使用基于主键的游标分页替代大偏移量分页。',
  },
  {
    pattern: /password\s+FROM|passwd\s+FROM|pwd\s+FROM/gi,
    severity: 'error' as const,
    category: 'security' as const,
    message: '安全风险：直接查询密码字段',
    suggestion: '不要在查询中返回密码字段，密码应使用哈希存储和验证。',
  },
  {
    pattern: /INSERT\s+INTO.*VALUES\s*\(/gi,
    severity: 'info' as const,
    category: 'best-practice' as const,
    message: 'INSERT 语句未指定列名',
    suggestion: '明确指定插入的列名，便于维护和避免表结构变更导致的问题。',
  },
  {
    pattern: /DROP\s+TABLE(?!\s+IF\s+EXISTS)/gi,
    severity: 'warning' as const,
    category: 'best-practice' as const,
    message: 'DROP TABLE 未检查表是否存在',
    suggestion: '使用 DROP TABLE IF EXISTS 避免表不存在时出错。',
  },
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

          const exists = issues.some(
            (i) => i.line === lineNum && i.message === rule.message
          )

          if (!exists) {
            issues.push({
              line: lineNum,
              severity: rule.severity,
              category: rule.category,
              message: rule.message,
              suggestion: rule.suggestion,
            })
          }
        }
      })
    }
  })

  if (language === 'java') {
    const lines = code.split('\n')
    lines.forEach((line, index) => {
      if (/Connection\s+\w+\s*=.*\.getConnection\(\)/.test(line)) {
        const afterLines = lines.slice(index + 1).join('\n')
        if (!afterLines.includes('close()') && !afterLines.includes('try-with')) {
          issues.push({
            line: index + 1,
            severity: 'error',
            category: 'performance',
            message: '资源泄漏：Connection 未确保关闭',
            suggestion: '使用 try-with-resources 语句确保连接关闭。',
          })
        }
      }
    })
  }

  return issues.sort((a, b) => a.line - b.line)
}

// Serve static files
app.use(express.static(__dirname))

// API routes
app.post('/api/code-review', async (req: Request, res: Response) => {
  try {
    const { code, language } = req.body

    if (!code || !language) {
      return res.status(400).json({ error: 'Missing required fields: code and language' })
    }

    if (!['java', 'mysql'].includes(language)) {
      return res.status(400).json({ error: 'Invalid language. Supported: java, mysql' })
    }

    await new Promise((resolve) => setTimeout(resolve, 800 + Math.random() * 800))

    const issues = analyzeCode(code, language)

    return res.json({
      issues,
      summary: {
        total: issues.length,
        errors: issues.filter((i) => i.severity === 'error').length,
        warnings: issues.filter((i) => i.severity === 'warning').length,
        suggestions: issues.filter((i) => i.severity === 'info').length,
      },
      timestamp: new Date().toISOString(),
    })
  } catch (error) {
    console.error('Code review error:', error)
    return res.status(500).json({ error: 'Internal server error' })
  }
})

// Handle SPA routing - serve index.html for all other routes
app.get('/', (req: Request, res: Response) => {
  res.sendFile(path.join(__dirname, 'index.html'))
})

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})
