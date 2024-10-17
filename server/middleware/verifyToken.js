import jwt from "jsonwebtoken";
import { createError } from "../error.js";

export const verifyToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return next(createError(401, "You are not authenticated!"));
    }

    const token = authHeader.split(" ")[1];
    if (!token) {
      return next(createError(401, "Token not found"));
    }

    const decoded = jwt.verify(token, process.env.JWT);
    req.user = decoded;
    next();
  } catch (err) {
    next(createError(403, "Invalid Token"));
  }
};
