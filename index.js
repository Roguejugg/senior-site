const express = require('express')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const path = require('path')
const { OpenAI } = require('openai')
const Datastore = require('nedb-promises')
const usersDB = Datastore.create('users.db') // Файловая бд, лень деплоить монго
const dotenv = require('dotenv').config({path:'config.env'})
const SECRET_KEY = process.env.JWT_KEY
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY })
const app = express()

async function getChatResponse(prompt) {
  try {
    const response = await openai.chat.completions.create({
      model: 'gpt-3.5-turbo',
      messages: [{ role: 'user', content: prompt }],
    })
    return response.choices[0].message.content
  } catch (error) {
    console.error('Error:', error)
    return null
  }
}

app.use(express.static('./views/'))
app.get('/', async (req, res) => {
  var token
  if(req.headers && req.headers.cookie){
    token = req.headers.cookie.split("token=")[1]
  } else{
    token = null
  }

  if (token == null) {
    return res.sendFile(__dirname + "/views/html/login.html")
  } else{
    try {
      const decoded = jwt.verify(token, SECRET_KEY)
      if(decoded){
        res.sendFile(__dirname + "/views/html/index.html")
      }
    } catch (err) {
      return res.sendFile(__dirname + "/views/html/login.html")
    }
  }
})

app.get('/logout', (req, res) => {
  res.clearCookie('token', { httpOnly: true, secure: true })
  res.redirect("/")
})

app.get('/reg', async (req, res) => {
  res.sendFile(__dirname + "/views/html/register.html")
})

const bodyParser = require('body-parser')
app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())

function isUsernameValid(username) {
  const allowedUsernameRegex = /^[a-zA-Z0-9._]*$/
  return allowedUsernameRegex.test(username)
}
function isPasswordValid(password) {
  const allowedCharactersRegex = /^[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]*$/
  return allowedCharactersRegex.test(password)
}

app.post('/gpt-ask', async (req, res) => {
  const question = req.body.question
  if(question && question != ""){
    res.send({error: false, response: await getChatResponse(question)})
  } else if(question == ""){
    res.send({error: true, errorText: "Message field cannot be empty"})
  }
})

app.post('/register', async (req, res) => {
  const username = req.body.username,
  password = req.body.password
  const users = await usersDB.find()
  if(
    username && password && username != "" && password != "" && 
    isUsernameValid(username) && isPasswordValid(password) && password.length >= 8 &&
    (users.some(user => user.username === username) == false)
  ){
    const hashedPassword = await bcrypt.hash(password, 10)
    await usersDB.insert({ username: username, password: hashedPassword })
    const token = jwt.sign({ username: username }, SECRET_KEY, { expiresIn: '24h' })
    res.status(200).json({ token })
  } else if(username == "" && password == ""){
    res.send({error: true, errorText: "All fields must not be empty"})
  } else if(isUsernameValid(username) == false){
    res.send({error: true, errorText: "You can use only digits and Latin letters for username"})
  } else if(isUsernameValid(password) == false){
    res.send({error: true, errorText: "You cannot use bad characters in password"})
  } else if(password.length < 8){
    res.send({error: true, errorText: "Password length must be 8+ characters length"})
  } else if(users.some(user => user.username === username)){
    res.send({error: true, errorText: "There is already a user with such username"})
  }
})

app.post('/login', async (req, res) => {
  const username = req.body.username,
  password = req.body.password
  const users = await usersDB.find()
  
  const user = users.find(u => u.username === username)
  if (!user) {
    return res.send({error: true, errorText: "User not found"})
  }
  
  const isMatch = await bcrypt.compare(password, user.password)
  if (!isMatch) {
    return res.send({error: true, errorText: "Invalid credentials"})
  }
  
  if(user && isMatch){
    const token = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '24h' })
    res.json({token: token})
  }
})

app.listen(3000, () => {
  console.log('Server running on port 3000')
})