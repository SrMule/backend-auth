import express, { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import morgan from 'morgan';
import dotenv from 'dotenv';
dotenv.config();

const app = express();
app.use(express.json())
app.use(morgan('dev'));
const port = 3000;

declare module 'express-serve-static-core' {
  interface Request {
    user?: any; 
  }
}

interface User {
  username: string,
  password: string
}

const usersBD: User[] = [];


function generateAccessToken(username: string) {
  const payload = {
    username,
    iat: Math.floor(Date.now() / 1000), // timestamp actual
  };
  return jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET as string, { expiresIn: '1h' });
}

function authenticateToken(req: Request, res: Response, next: any) {
  // Verificar si el encabezado de autorización está presente
  if (!req.headers['authorization']) {
    return res.status(401).send('Encabezado de autorización no proporcionado');
  }

  const authHeader = req.headers['authorization'];

  // Verificar el formato del encabezado de autorización
  const authHeaderParts = authHeader.split(' ');
  if (authHeaderParts.length !== 2 || authHeaderParts[0] !== 'Bearer') {
    return res.status(401).send('Formato de encabezado de autorización inválido');
  }

  // Extraer el token
  const token = authHeaderParts[1];

  // Verificar el token
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET as string, (err: any, user: any) => {
    if (err) {
      return res.status(403).send('Token de autenticación inválido');
    }
    req.user = user;
    next();
  });
}

// Ruta para registro de usuarios
app.post('/register', async (req, res) => {
  try {
    // Encriptar la contraseña
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user: User = { username: req.body.username, password: hashedPassword };
    usersBD.push(user);
    res.status(201).send('Usuario registrado exitosamente');
    console.log(usersBD);
  } catch {
    res.status(500).send('Error al registrar el usuario');
  }
});

// Ruta para iniciar sesión
app.post('/login', async (req, res) => {
  const user = usersBD.find(user => user.username === req.body.username);
  if (user == null) {
    return res.status(400).send('Usuario no encontrado');
  }
  try {
    if (await bcrypt.compare(req.body.password, user.password)) {
      // Si la contraseña coincide, generar token de autenticación
      const accessToken = generateAccessToken(user.username);
      const authHeader = `Bearer ${accessToken}`;
      console.log(authHeader);
      res.json({ authHeader });
    } else {
      res.status(401).send('Credenciales inválidas');
    }
  } catch {
    res.status(500).send('Error al intentar iniciar sesión');
  }
});

app.get('/protected', authenticateToken, (req, res) => {
  res.send('Ruta protegida. Bienvenido!');
});

app.listen(port, () => {
  console.log(`Servidor corriendo en http://localhost:${port}`);
});
