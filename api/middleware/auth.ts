import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';



export const authMiddleware = (req: Request, res: Response, next: NextFunction) => {
  const token = req.cookies.access_token;

  
  if (!token) {
    res.status(401).json({ message: 'No token provided' });
    return;
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as { _id: string; role: string };
    req.user = { id: decoded._id, role: decoded.role };
   
   
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
    return;
  }
};

export const roleMiddleware = (role: 'recruiter' | 'candidate') => (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  console.log("Token:", req.user?.id);
  if (req.user?.role !== role)  {
    res.status(403).json({ message: 'Access denied' })
     return;
    };
  next();
};