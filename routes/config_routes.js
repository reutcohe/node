const indexR = require("./index");
const usersR = require("./users");
const scorsR = require("./scores");



exports.routesInit = (app) => {
  app.use("/", indexR);
  app.use("/users", usersR);
  app.use("/scores", scorsR)


}