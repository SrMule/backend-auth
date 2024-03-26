import express from 'express';
import routes from './routes';
import {configureMiddlewares} from './middlewares';

const app = express();
const port = 3000;

configureMiddlewares(app);

app.use(routes);

app.listen(port, () => {
  console.log(`Escuchando puerto ${port}`);
});
