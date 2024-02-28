const express = require('express')
const path = require('path')
const {open} = require('sqlite')
const sqlite3 = require('sqlite3')
const app = express()
const jsonMiddleware = express.json()
app.use(jsonMiddleware)
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
let db = null

const dbPath = path.join(__dirname, 'twitterClone.db')

const initializeDbAndServer = async () => {
  try {
    db = await open({filename: dbPath, driver: sqlite3.Database})
    console.log('Database connected')

    app.listen(3000, () => {
      console.log('Server is running at http://localhost:3000')
    })
  } catch (error) {
    console.error(`Error connecting to database: ${error.message}`)
    process.exit(1)
  }
}

initializeDbAndServer()

// User Register
//API1
app.post('/register/', async (req, res) => {
  const {username, password, name, gender} = req.body

  // Hash the password
  const hashedPassword = await bcrypt.hash(password, 10)

  try {
    // Check if the user already exists
    const checkUserQuery = `SELECT * FROM user WHERE username = ?`
    const existingUser = await db.get(checkUserQuery, [username])

    if (existingUser) {
      return res.status(400).send('User already exists')
    }

    // Check if the password meets the minimum length requirement
    if (password.length < 6) {
      return res.status(400).send('Password is too short')
    }

    // Insert the new user into the database
    const insertUserQuery = `
      INSERT INTO User (username, password, name, gender)
      VALUES (?, ?, ?, ?)
    `
    await db.run(insertUserQuery, [username, hashedPassword, name, gender])

    // Send a success response
    res.send('User created successfully')
  } catch (error) {
    console.error('Error during registration:', error.message)
    res.status(500).send('Internal Server Error')
  }
})

//Api2
app.post('/login', async (req, res) => {
  const {username, password} = req.body
  try {
    const selectUserQuery = 'SELECT * FROM user WHERE username = ?'
    const dbUser = await db.get(selectUserQuery, [username])

    if (!dbUser) {
      return res.status(400).send('Invalid user')
    }

    const isPasswordMatch = await bcrypt.compare(password, dbUser.password)
    if (isPasswordMatch) {
      const payload = {
        username: username,
        user_id: dbUser.user_id,
        tweet_id: dbUser.tweet_id,
      }
      let jwtToken = jwt.sign(payload, 'Abcdef123')
      res.send({jwtToken})
    } else {
      res.status(400).send('Invalid password')
    }
  } catch (error) {
    console.error(`Error logging in: ${error.message}`)
    res.status(500).send('Internal Server Error')
  }
})
//const jwt = require('jsonwebtoken');

async function authentication(req, res, next) {
  try {
    let jwtToken
    const authHeader = req.headers['authorization']
    if (authHeader !== undefined) {
      jwtToken = authHeader.split(' ')[1]
    }
    if (jwtToken === undefined) {
      return res.status(401).send('Invalid JWT Token')
    }

    jwt.verify(jwtToken, 'Abcdef123', async (err, payload) => {
      if (err) {
        return res.status(401).send('Invalid JWT Token')
      } else {
        req.username = payload.username
        req.user_id = payload.user_id
        req

        next() // Proceed to the next middleware or handler
      }
    })
  } catch (error) {
    console.error('Error in authentication middleware:', error.message)
    res.status(500).send('Internal Server Error')
  }
}
//API3
app.get('/user/tweets/feed/', authentication, async (req, res) => {
  const queryuser = `SELECT u.username, t.tweet, t.date_time AS dateTime
    FROM User u
    JOIN Follower f ON u.user_id = f.following_user_id
    JOIN Tweet t ON t.user_id = f.following_user_id
    ORDER BY u.user_id
    LIMIT 4;`
  try {
    const dbResponse = await db.all(queryuser)
    res.send(dbResponse)
  } catch (err) {
    console.log(`Error in getting:${err.message}`)
    res.status(500).send('Internal Server Error')
  }
})
//API4
app.get('/user/following/', authentication, async (req, res) => {
  const {user_id} = req
  const queryuser = `SELECT DISTINCT u.username
    FROM User u
    JOIN Follower f ON u.user_id = f.following_user_id
    WHERE f.follower_user_id = ?
      ;`
  try {
    const dbResponse = await db.all(queryuser, [user_id])
    res.send(dbResponse)
  } catch (err) {
    console.log(`Error in getting:${err.message}`)
    res.status(500).send('Internal Server Error')
  }
})

//API 5
app.get('/user/following/', authentication, async (req, res) => {
  const {user_id} = req
  const query = `select u.name from user as u inner join follower as f on u.user_id=f.follower_user_id
  where u.user_id=? `
  try {
    const dbResponse = await db.all(query, [user_id])
    res.send(dbResponse)
  } catch (err) {
    console.log(`Error in getting followers:${err.message}`)
    res.status(500).send('Internal Server Error')
  }
})
//API 6

app.get('/tweets/:tweetId/', authentication, async (req, res) => {
  const {user_id, tweet_id} = req
  const userFollowQuery = `
    SELECT COUNT(*) AS count
    FROM follower
    WHERE follower_user_id=? and following_user_id = (
      SELECT user_id FROM tweet WHERE tweet_id = ?
    )
  `

  //console.log(userFollowQuery)
  try {
    const {count} = await db.get(userFollowQuery, [user_id, tweet_id])
    console.log(count)
    if (count === 0) {
      return res.status(401).send('Invalid Request')
    }
    const tweetDetailsQuery = `
      SELECT
        t.tweet,
        COUNT(l.like_id) AS likes,
        COUNT(r.reply_id) AS replies,
        t.date_time AS dateTime
      FROM
        tweet AS t
        LEFT JOIN reply AS r ON t.tweet_id = r.tweet_id
        LEFT JOIN like AS l ON t.tweet_id = l.tweet_id
      WHERE
        t.tweet_id = ? AND
        t.user_id = ?
      GROUP BY
        t.tweet_id;
    `

    const tweetDetails = await db.get(tweetDetailsQuery, [tweet_id, user_id])
    res.json(tweetDetails)
  } catch (error) {
    console.error(`Error retrieving tweet details: ${error.message}`)
    res.status(500).send('Internal Server Error')
  }
})
// Api 7
app.get('/tweets/:tweetId/likes/', authentication, async (req, res) => {
  const {user_id, tweet_id} = req

  try {
    // Check if the logged-in user follows the user who posted the requested tweet
    const followQuery = `
      SELECT COUNT(*) AS count 
      FROM follower 
      WHERE follower_user_id = ? 
      AND following_user_id = (
        SELECT user_id FROM tweet WHERE tweet_id = ?
      )
    `
    const {count} = await db.get(followQuery, [user_id, tweet_id])

    // If the user does not follow the user who posted the tweet, return 401 (Unauthorized)
    if (count === 0) {
      return res.status(401).send('Invalid Request')
    }

    // Fetch the list of usernames who liked the tweet
    const likesQuery = `
      SELECT u.username AS username
      FROM likes l
      JOIN user u ON l.user_id = u.user_id
      WHERE l.tweet_id = ?
    `

    const likedUsers = await db.all(likesQuery, [tweet_id])
    console.log(likedUsers)

    // Extract usernames from the result and send them in the response
    const likes = likedUsers.map(user => user.username)
    res.json({likes})
  } catch (error) {
    console.error(`Error retrieving tweet likes: ${error.message}`)
    res.status(500).send('Internal Server Error')
  }
})
