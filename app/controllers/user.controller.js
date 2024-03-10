exports.allAccess = (req, res) => {
  res.status(200).send("Public Content.");
};

const db = require("../models");
const User = db.user;


exports.userBoard = async (req, res) => {
  const userId = req.userId;
  let user;
  try {
      user = await User.findById(userId,"-password");
  } catch (error) {
      return new Error(error);   
  }
  if(!user) {
      return res.status(404).json({message:"No User Found"});
  }
  return res.status(200).json({user});
};

exports.adminBoard = async (req, res) => {
  const userId = req.userId;
  let user;
  try {
      user = await User.findById(userId,"-password");
  } catch (error) {
      return new Error(error);   
  }
  if(!user) {
      return res.status(404).json({message:"No User Found"});
  }
  return res.status(200).json({user});
};

exports.moderatorBoard = async (req, res) => {
  const userId = req.userId;
  let user;
  try {
      user = await User.findById(userId,"-password");
  } catch (error) {
      return new Error(error);   
  }
  if(!user) {
      return res.status(404).json({message:"No User Found"});
  }
  return res.status(200).json({user});
};
