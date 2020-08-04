const express = require('express')
const bodyParser = require('body-parser')
const crypto = require('crypto');
const db = require('./queries')
const cors = require('cors')
const jwt = require('jsonwebtoken');
const config = require('./config.json');

const app = express()
const port = 3000

app.use(cors())
app.use(bodyParser.json())
app.use(
  bodyParser.urlencoded({
    extended: true,
  })
)

app.get('/', (request, response) => {
    response.json({ info: 'Node.js, Express, and Postgres API' })
})

app.listen(port, () => {
    console.log(`App running on port ${port}.`)
})

app.post('/api/signup', (req, res) => {
    const body = req.body;
    let data;

    if (body.encryptionType === 'HMAC') {
        data = hmacSaltEncryption(body.password);
    } else {
        data = saltPepper512Encryption(body.password);
    }

    Object.assign(data, {login: body.login});

    db.createUser(data, res);
});

app.post('/api/signin', (req, res) => {
    const {login, password} = req.body;

    db.getUserByLogin(login).then(result => {
        let user = result.rows[0];
        let data = encryptHMAC(password, user.salt);
        let token = jwt.sign({ userId: user.id }, config.secret);

        if (user.password_hash = data.passwordHash) {
            res.status(200).json({
                id: user.id,
                login: user.login,
                token: token
            }).send();
        }
    });
});

async function verifyToken(req) {
    const authHeader = req.headers.authorization;
    const token = authHeader.replace('Bearer ', '');
    
    const decoded = await jwt.verify(token, config.secret);

    const { rows } = await db.getUserById(decoded.userId);
    
    return rows[0];
}

app.get('/api/users', db.getUsers)
app.get('/api/users/:login', (req, res) => {
    const login = req.params.login;
    
    db.getUserByLogin(login).then(result => {
        let user = result.rows[0];
        res.status(200).json({id: user.id, login: user.login}).send()
    });
})

app.put('/api/users/:id', db.updateUser)
app.delete('api/users/:id', db.deleteUser)

app.get('/api/passwords', (req, res) => {
    verifyToken(req).then(user => {
        db.getPasswords(user.login, req, res)
    });
});

app.post('/api/passwords', (req, res) => {
    const { application, password } = req.body;
    
    verifyToken(req).then(user => {
        let encryptedData = encryptPassword(password, user.password_hash);
        db.addPassword(encryptedData, user.login, req, res);
    });
});

app.get('/api/passwords/:id', (req, res) => {
    const id = req.params.id;

    verifyToken(req).then(user => {
        db.getPasswordById(id).then(result => {
            const data = result.rows[0];
            const encryptedData = {iv: data.iv, encryptedData: data.password}
            const decryptedPassword = decrypt(encryptedData, user.password_hash);
            res.status(200).json({password: decryptedPassword}).send();
        })
    });
});

app.delete('/api/passwords/:id', (req, res) => {
    const id = parseInt(req.params.id);

    verifyToken(req).then(user => {
        db.deletePassword(user, id, req, res);
    })
});

function encryptHMAC(password, salt) {
    const hash = crypto.createHmac('sha256', salt);
    hash.update(password);
    const value = hash.digest('hex');
    return {
        salt,
        passwordHash: value
    }
}

function hmacSaltEncryption(userpassword) {
    const salt = crypto.randomBytes(8).toString('hex');
    const passwordData = encryptHMAC(userpassword, salt);
    
    return passwordData;
}


function encrypt512(password) {
    const hash = crypto.createHash('sha512')
    hash.update(password)
    const value = hash.digest('hex');
    return value;
}

function saltPepper512Encryption(userpassword) {
    const pepper = '$t4l3Z4pI$4NYPI3PRZ'
    const salt = crypto.randomBytes(8).toString('hex');
    const x = salt + pepper + userpassword;
    const passwordData = encrypt512(x);

    return {
        salt,
        passwordHash: passwordData
    };
}

function encryptPassword(password, key) {
    const iv = crypto.randomBytes(16);

    const _key = crypto.createHash("md5").update(key).digest('hex');

    let cipher = crypto.createCipheriv("aes256", _key, iv);
    let encrypted = cipher.update(password);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return { iv: iv.toString('hex'), encryptedData: encrypted.toString('hex') };
}

function decrypt(data, key) {
    const _key = crypto
        .createHash("md5")
        .update(key)
        .digest('hex');

    let iv = Buffer.from(data.iv, 'hex');
    let encryptedText = Buffer.from(data.encryptedData, 'hex');
    let decipher = crypto.createDecipheriv('aes256', _key, iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}
