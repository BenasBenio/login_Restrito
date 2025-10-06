const express = require('express');
const MongoClient = require('mongodb').MongoClient; 
const session = require('express-session');
const bcrypt = require('bcrypt');

const app = express();
const port = 3000;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(session({
    secret: 'segredo-hiper-secreto',
    resave: false,
    saveUninitialized: true,
}));

const urlMongo = 'mongodb://localhost:27017';
const nomeBanco = 'sistemaLogin';

app.get('/registro', (req, res) => {
    res.sendFile(__dirname + '/views/registro.html');
});

app.post('/registro', async (req, res) => {
    const cliente = new MongoClient(urlMongo, { useUnifiedTopology: true });
    try {
        await cliente.connect();
        const banco = cliente.db(nomeBanco);
        const colecaoUsuarios = banco.collection('usuarios');

        const usuarioExistente = await colecaoUsuarios.findOne({ usuario: req.body.usuario });

        if (usuarioExistente) {
            res.send('Usuário já existente! Tente outro nome de usuário.');
        } else {
            const senhaCriptografada = await bcrypt.hash(req.body.senha, 10);

            await colecaoUsuarios.insertOne({
                usuario: req.body.usuario,
                senha: senhaCriptografada
            });
            res.redirect('/login');
        }
    } catch (erro) {
        console.error(erro);
        res.send('Erro ao registrar o usuário.');
    } finally {
        await cliente.close();
    }
});

app.get('/login', (req, res) => {
    res.sendFile(__dirname + '/views/login.html');
});

app.post('/login', async (req, res) => {
    const cliente = new MongoClient(urlMongo, { useUnifiedTopology: true });
    try {
        await cliente.connect();
        const banco = cliente.db(nomeBanco);
        const colecaoUsuarios = banco.collection('usuarios');

        const usuario = await colecaoUsuarios.findOne({ usuario: req.body.usuario });

        if (usuario && await bcrypt.compare(req.body.senha, usuario.senha)) {
            req.session.usuario = req.body.usuario; 
            res.redirect('/bemVindo');
        } else {
            res.redirect('/erro');
        }
    } catch (erro) {
        console.error(erro);
        res.send('Erro ao realizar o login.');
    } finally {
        await cliente.close();
    }
});

function protegerRota(req, res, proximo) {
    if (req.session.usuario) {
        proximo();
    } else {
        res.redirect('/login');
    }
}

app.get('/bemVindo', protegerRota, (req, res) => {
    res.sendFile(__dirname + '/views/bemVindo.html');
});

app.get('/erro', (req, res) => {
    res.sendFile(__dirname + '/views/erro.html');
});

app.get('/sair', (req, res) => {
    req.session.destroy((err) => { 
        if (err) {
            return res.send('Erro ao sair!');
        }
        res.redirect('/login');
    });
});

app.listen(port, () => {
    console.log(`Servidor rodando na porta http://localhost:${port}/login`);
});
