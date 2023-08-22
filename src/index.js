require('dotenv').config()
const express = require('express')
const app = express()

const mongoose = require('mongoose');
const cors = require('cors');

mongoose.connect(process.env.DB_URL);
const db = mongoose.connection;

db.on('error', (error)=> console.log(error));
db.once('open',()=>console.log('Conectado a base de datos de usuarios'));

app.use(express.json());
app.use(cors());

const routerUsuarios = require('./routes/usuarios');
app.use('/usuarios', routerUsuarios);

app.listen(3001, ()=> console.log('RR: microservicio de usuarios iniciado correctamente'))