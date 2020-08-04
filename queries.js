const Pool = require('pg').Pool
const pool = new Pool({
  user: 'me',
  host: 'localhost',
  database: 'password_manager',
  password: 'maroko13',
  port: 5432,
})

const getUsers = (request, response) => {
    pool.query('SELECT * FROM users ORDER BY id ASC', (error, results) => {
      if (error) {
        throw error
      }
      response.status(200).json(results.rows)
    })
}

const getUserByLogin = (login) => {
    return pool.query('SELECT * FROM users WHERE login = $1', [login])
    // response.status(200).json(results.rows)
}

const getUserById = (id) => {
    return pool.query('SELECT * FROM users WHERE id = $1', [id])
}

const createUser = (data, response) => {
    const { login, passwordHash, salt } = data
  
    pool.query('INSERT INTO users (login, password_hash, salt) VALUES ($1, $2, $3)', [login, passwordHash, salt], (error, results) => {
      if (error) {
        throw error
      }
      response.status(201).json(results.insertId).send();
    })
}

const updateUser = (data, response) => {
    const id = parseInt(request.params.id)
    const { login, passwordHash, salt } = data
  
    pool.query(
      'UPDATE users SET login = $1, passwordHash = $2, salt = $3 WHERE id = $4',
      [login, passwordHash, salt, id],
      (error, results) => {
        if (error) {
          throw error
        }
        response.status(200).json(id).send();
      }
    )
}

const deleteUser = (request, response) => {
    const id = parseInt(request.params.id)
  
    pool.query('DELETE FROM users WHERE id = $1', [id], (error, results) => {
      if (error) {
        throw error
      }
      response.status(200).send(`User deleted with ID: ${id}`)
    })
}

const getPasswords = (login, request, response) => {
    pool.query('SELECT passwords.id, passwords.password, passwords.web_address FROM passwords INNER JOIN users ON passwords.login=users.login WHERE users.login=$1 ORDER BY passwords.id ASC', [login], (error, results) => {
        if (error) {
          throw error
        }
        response.status(200).json(results.rows)
      })
}

const addPassword = (data, login, request, response) => {
    const { application, password } = request.body
   
    pool.query('INSERT INTO passwords (password, iv, web_address, login) VALUES ($1, $2, $3, $4)', [data.encryptedData, data.iv, application, login], (error, results) => {
      if (error) {
        throw error
      }
      response.status(200).json(results.insertId).send();
    })
}

const getPasswordById = (id, request, response) => {   
    return pool.query('SELECT * from passwords WHERE id = $1;', [id]);
}

const deletePassword = (user, id, request, response) => {
    const query = 'DELETE FROM passwords WHERE (login = $1 AND id = $2)';
    pool.query(query, [user.login, id], (error, results) => {
      if (error) {
        throw error
      }
      response.status(200).json(id).send();
    })
}

module.exports = {
    getUsers,
    getUserByLogin,
    getUserById,
    createUser,
    updateUser,
    deleteUser,
    getPasswords,
    getPasswordById,
    addPassword,
    deletePassword,
}