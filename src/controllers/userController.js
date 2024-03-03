import User from "../models/User";
import bcrypt from "bcrypt";
import fetch from "node-fetch";

export const getJoin = (req, res) => res.render("join", { pageTitle: "Join" });
export const postJoin = async (req, res) => {
    const { name, username, email, password, password2, location } = req.body;
    const pageTitle = "Join";
    if (password !== password2) {
        return res.status(400).render("join", {
            pageTitle,
            errorMessage: "Passwords do not match.",
        });
    }

    const exists = await User.exists({ $or: [{ username }, { email }] });
    if (exists) {
        return res.status(400).render("join", {
            pageTitle,
            errorMessage: "This username/email is already taken.",
        });
    }
    try {
        await User.create({
            name,
            username,
            email,
            password,
            location,
        });
        return res.redirect("/login");
    } catch (error) {
        return res.status(400).render("join", {
            pageTitle: "Upload Video",
            errorMessage: error._message,
        });
    }
};

export const getLogin = (req, res) =>
    res.render("login", { pageTitle: "Login" });

export const postLogin = async (req, res) => {
    const { username, password } = req.body;
    const pageTitle = "Login";
    //check if account exists
    const user = await User.findOne({ username, socialOnly: false });
    if (!user) {
        return res.status(404).render("login", {
            pageTitle,
            errorMessage: "An account with this username does not exists.",
        });
    }

    //check if password correct
    const checkPassword = await bcrypt.compare(password, user.password);
    if (!checkPassword) {
        return res.status(404).render("login", {
            pageTitle,
            errorMessage: "Wrong password",
        });
    }
    //session initialized!
    req.session.loggedIn = true;
    req.session.user = user;

    return res.redirect("/");
};

export const startGithubLogin = (req, res) => {
    const baseUrl = `https://github.com/login/oauth/authorize`;
    const config = {
        // 깃허브가 원하는 대로 스펠링도 다 맞아야한다. clientId가 아닌 client_id
        client_id: process.env.GH_CLIENT,
        allow_signup: false,
        scope: "read:user user:email",
    };
    const params = new URLSearchParams(config).toString();
    const finalUrl = `${baseUrl}?${params}`;
    return res.redirect(finalUrl);
};

export const finishGithubLogin = async (req, res) => {
    const baseUrl = "https://github.com/login/oauth/access_token";
    const config = {
        client_id: process.env.GH_CLIENT,
        client_secret: process.env.GH_SECRET,
        code: req.query.code,
    };
    const params = new URLSearchParams(config).toString();
    const finialUrl = `${baseUrl}?${params}`;
    const tokenRequest = await (
        await fetch(finialUrl, {
            method: "POST",
            headers: {
                Accept: "application/json",
            },
        })
    ).json();

    if ("access_token" in tokenRequest) {
        const { access_token } = tokenRequest;
        const apiUrl = "https://api.github.com";
        const userData = await (
            await fetch(`${apiUrl}/user`, {
                headers: {
                    Authorization: `token ${access_token}`,
                },
            })
        ).json();

        const emailData = await (
            await fetch(`${apiUrl}/user/emails`, {
                headers: {
                    Authorization: `token ${access_token}`,
                },
            })
        ).json();
        return res.send(emailData);
        const emailObj = emailData.find(
            (email) => email.primary === true && email.verified === true
        );
        if (!emailObj) {
            return res.redirect("/login");
        }
        // 일반 pw로 생성한 계정이더라도 상관없이 처리
        let user = await User.findOne({ email: emailObj.email });
        if (!user) {
            //create an account
            user = await User.create({
                avatarUrl: userData.avatar_url,
                name: userData.name,
                username: userData.login,
                email: emailObj.email,
                password: "", // password isn't required when creating account by social login
                socialOnly: true, // but notify social Logined
                location: userData.location,
            });
        }
        //auto login
        req.session.loggedIn = true;
        req.session.user = user;
        return res.redirect("/");
    } else {
        return res.redirect("/login");
    }
};

export const getEdit = (req, res) => {
    return res.render("edit-profile", {
        pageTitle: "Edit Profile",
    });
};

export const postEdit = async (req, res) => {
    const {
        session: {
            user: { _id, avatarUrl }, //id가 아닌 _id임을 주의(세선을 console.log 찍어서 확인)
        },
        body: { name, email, username, location },
        file,
    } = req;
    console.log(file);
    const updatedUser = await User.findByIdAndUpdate(
        _id,
        {
            avatarUrl: file ? file.path : avatarUrl,
            name,
            email,
            username,
            location,
        },
        { new: true } //옵션 줘서 업데이트 이후의 객체 반환
    );
    req.session.user = updatedUser;
    return res.redirect("/users/edit");
};

export const logout = (req, res) => {
    req.session.destroy();
    return res.redirect("/");
};

export const getChangePassword = (req, res) => {
    //깃허브 가입 계정이면 애초에 비번이 없으니까 막아라
    if (req.session.user.socialOnly) {
        return res.redirect("/");
    }
    return res.render("users/change-password", {
        pageTitle: "Change Password",
    });
};

export const postChangePassword = async (req, res) => {
    const {
        session: {
            user: { _id },
        },
        body: { oldPassword, newPassword, newPasswordConfirmation },
    } = req;
    const user = await User.findById(_id);
    const passwordCheck = await bcrypt.compare(oldPassword, user.password);
    if (!passwordCheck) {
        return res.status(400).render("users/change-password", {
            pageTitle: "Change Password",
            errorMessage: "The current password is incorrect",
        });
    }
    if (newPassword !== newPasswordConfirmation) {
        // 브라우저는 status 코드만을 인식
        return res.status(400).render("users/change-password", {
            pageTitle: "Change Password",
            errorMessage: "The password does nt match the confirmation",
        });
    }

    user.password = newPassword;
    await user.save(); // pre middleware가 작동하여 비번 자동 해시

    //send notification
    return res.redirect("/users/logout");
};

export const see = (req, res) => res.send("See User");
