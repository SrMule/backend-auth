import express, { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { authenticateToken } from './middlewares';

const router = express.Router();

interface User {
  username: string,
  password: string
}

const usersBD: User[] = [];

function generateAccessToken(username: string) {
  const payload = {
    username,
    iat: Math.floor(Date.now() / 1000),
  };
  return jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET as string, { expiresIn: '1h' });
}

router.post('/register', async (req: Request, res: Response) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user: User = { username: req.body.username, password: hashedPassword };
    usersBD.push(user);
    res.status(201).send('Usuario registrado exitosamente');
  } catch {
    res.status(500).send('Error al registrar el usuario');
  }
});

router.post('/login', async (req: Request, res: Response) => {
  const user = usersBD.find(user => user.username === req.body.username);
  if (user == null) {
    return res.status(400).send('Usuario no encontrado');
  }
  try {
    if (await bcrypt.compare(req.body.password, user.password)) {
      const accessToken = generateAccessToken(user.username);
      const authHeader = `Bearer ${accessToken}`;
      res.json({ authHeader });
    } else {
      res.status(401).send('Credenciales inválidas');
    }
  } catch {
    res.status(500).send('Error al intentar iniciar sesión');
  }
});

router.get('/protected', authenticateToken, (req: Request, res: Response) => {
  res.send('Ruta protegida. Bienvenido!');
});

export default router;
