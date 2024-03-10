const jwt = require("jsonwebtoken");
const config = require("../config/auth.config.js");
const db = require("../models");
const asyncHandler = require('express-async-handler')
const cookieParser = require('cookie-parser');

const User = db.user;
const Role = db.role;

const verifyToken = asyncHandler(async (req, res, next) => {
  const cookies = req.headers.cookie;
  if(!cookies)
  {
    return res.status(403).send({ message: "No cookie provided!" });
  }
  const token = cookies.split("=")[1];
  // console.log(token);
  // let token = req.headers["x-access-token"];
  // const token = req.headers.authorization;

  if (!token) {
    return res.status(403).send({ message: "No token provided!" });
  }

  jwt.verify(token,
            process.env.JWT_SECRET_KEY,
            (err, decoded) => {
              if (err) {
                return res.status(401).send({
                  message: "Unauthorized!",
                });
              }
              req.userId = decoded.id;
              next();
            });
            
});

const isAdmin = (req, res, next) => {
  User.findById(req.userId).exec((err, user) => {
    const userId = req.userId;
    if (err) {
      res.status(500).send({ message: err });
      return;
    }

    Role.find(
      {
        _id: { $in: user.roles }
      },
      (err, roles) => {
        if (err) {
          res.status(500).send({ message: err });
          return;
        }

        for (let i = 0; i < roles.length; i++) {
          if (roles[i].name === "admin") {
            next();
            return;
          }
        }

        res.status(403).send({ message: "Require Admin Role!" });
        return;
      }
    );
  });
};

const isModerator = (req, res, next) => {
  const userId = req.userId;
  User.findById(req.userId).exec((err, user) => {
    if (err) {
      res.status(500).send({ message: err });
      return;
    }

    Role.find(
      {
        _id: { $in: user.roles }
      },
      (err, roles) => {
        if (err) {
          res.status(500).send({ message: err });
          return;
        }

        for (let i = 0; i < roles.length; i++) {
          if (roles[i].name === "moderator") {
            next();
            return;
          }
        }

        res.status(403).send({ message: "Require Moderator Role!" });
        return;
      }
    );
  });
};

const authJwt = {
  verifyToken,
  isAdmin,
  isModerator
};
module.exports = authJwt;
