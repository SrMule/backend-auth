import express, { Request, Response, NextFunction } from 'express';
import morgan from 'morgan';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

declare module 'express-serve-static-core' {
  interface Request {
    user?: any; 
  }
}

const configureMiddlewares = (app: express.Application) => {
    app.use(express.json());
    app.use(morgan('dev'));
};

function authenticateToken(req: Request, res: Response, next: NextFunction) {
  if (!req.headers['authorization']) {
    return res.status(401).send('Encabezado de autorización no proporcionado');
  }

  const authHeader = req.headers['authorization'];

  const authHeaderParts = authHeader.split(' ');
  if (authHeaderParts.length !== 2 || authHeaderParts[0] !== 'Bearer') {
    return res.status(401).send('Formato de encabezado de autorización inválido');
  }

  const token = authHeaderParts[1];

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET as string, (err: any, user: any) => {
    if (err) {
      return res.status(403).send('Token de autenticación inválido');
    }
    req.user = user;
    next();
  });
}

export { configureMiddlewares, authenticateToken };
