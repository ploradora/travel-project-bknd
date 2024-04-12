import express, {Request, Response, Express} from "express";
import dotenv from 'dotenv';
// by calling the express function, the app is created
const app: Express = express();

dotenv.config();
const bodyParser = require('body-parser');
const {body, validationResult} = require('express-validator');
const bcrypt = require('bcrypt');

const PORT = 4012;

app.use(bodyParser.json());

interface UserInterface {
  email: string;
  password: string;
}

const users: UserInterface[] = [];

app.post('/register', 
[
  body('email').isEmail().withMessage('Invalid email address.'),
  body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long.'),
], async (req: Request, res: Response) => {

  const {email, password} = req.body;
  const errors = validationResult(req);

  if(!errors.isEmpty()) {
    return res.status(400).json({errors:errors.array()})
  }

  if(users.find(users => users.email === email)) {
    return res.status(400).json({errors: [{msg: 'Email already exists'}]})
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      email,
      password: hashedPassword,
    };
  
    users.push(newUser); 
    return res.status(201).json({ message: 'Successfully registered' });
  } catch {
    console.error('Error hashing password:', errors);
    return res.status(500).json({ errors: [{msg:'Internal server error.' }]});
  }
})

app.post('/login', async (req: Request, res: Response) => {
    const {email} = req.body;
    const user = users.find(user => user.email === email);

    if(user == null) {
      return res.status(400).send('Cannot find user')
    }

    try {
      if(await bcrypt.compare(req.body.password, user.password)) {
        res.send('Success')
      } else {
        res.send('Not allowed')
      }
    } catch {
      res.status(500).send();
    }
})

app.get('/users', (req: Request, res: Response) => {
  res.status(200).json(users)
})

// running the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});