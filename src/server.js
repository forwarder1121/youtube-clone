import express from "express";
import morgan from "morgan";
import session from "express-session";
import MongoStore from "connect-mongo";
import rootRouter from "./routers/rootRouter";
import userRouter from "./routers/userRouter";
import videoRouter from "./routers/videoRouter";
import { localsMiddleware } from "./middlewares";

const app = express();

const logger = morgan("dev");

app.set("view engine", "pug");
app.set("views", process.cwd() + "/src/views");
app.use(logger);
app.use(express.urlencoded({ extended: true }));
app.use(
    session({
        secret: process.env.COOKIE_SECRET,
        resave: false,
        saveUninitialized: false,
        store: MongoStore.create({
            mongoUrl: process.env.DB_URL,
        }),
    })
);

//session middleware must be called before
app.use(localsMiddleware);

app.use((req, res, next) => {
    req.sessionStore.all((error, sessions) => {
        //console.log(sessions);
        next();
    });
});

app.use("/", rootRouter);
app.use("/uploads", express.static("uploads"));
app.use("/videos", videoRouter);
app.use("/users", userRouter);

export default app;
