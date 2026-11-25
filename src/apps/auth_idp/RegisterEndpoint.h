#pragma once
#include <string>

inline std::string
getRegisterPageHtml(const std::string& clientId, const std::string& redirectUri, const std::string& state, const std::string& scope) {
    return R"(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - SNode.C Identity Provider</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); min-height: 100vh; display: flex; justify-content: center; align-items: center; color: #e8e8e8; }
        .container { background: rgba(255,255,255,0.05); backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 40px; width: 100%; max-width: 400px; box-shadow: 0 8px 32px 0 rgba(0,0,0,0.37); }
        h1 { text-align: center; font-size: 1.6rem; font-weight: 600; margin-bottom: 32px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; font-size: 14px; color: #ccc; }
        input { width: 100%; padding: 12px; background: rgba(255,255,255,0.1); border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; color: #fff; font-size: 16px; }
        input:focus { outline: none; border-color: #4cc9f0; }
        button { width: 100%; padding: 14px; background: #4cc9f0; color: #1a1a2e; border: none; border-radius: 8px; font-size: 16px; font-weight: bold; cursor: pointer; }
        .footer { text-align: center; margin-top: 24px; font-size: 0.85rem; color: #888; }
        .footer a { color: #4cc9f0; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Register Account</h1>
        <form method="POST" action="/auth/register">
            <input type="hidden" name="client_id" value=")" +
           clientId + R"(" />
            <input type="hidden" name="redirect_uri" value=")" +
           redirectUri + R"(" />
            <input type="hidden" name="state" value=")" +
           state + R"(" />
            <input type="hidden" name="scope" value=")" +
           scope + R"(" />
            <div class="form-group">
                <label>Username</label>
                <input type="text" name="username" required placeholder="Choose a username">
            </div>
            <div class="form-group">
                <label>Email</label>
                <input type="email" name="email" required placeholder="Enter your email">
            </div>
            <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" required placeholder="Create a password">
            </div>
            <button type="submit">Create Account</button>
        </form>
        <div class="footer"><a href="/auth/login?client_id=)" +
           clientId + R"(&redirect_uri=)" + redirectUri + R"(&state=)" + state + R"(&scope=)" + scope +
           R"(">Already have an account? Login here</a></div>
    </div>
</body>
</html>
    )";
}

inline std::string getSuccessPageHtml(const std::string& title, const std::string& message) {
    return R"(<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Success</title>
    <style>
        body { font-family: -apple-system, sans-serif; background: #1a1a2e; color: #e8e8e8; min-height: 100vh; display: flex; justify-content: center; align-items: center; }
        .card { background: rgba(255,255,255,0.05); border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 40px; max-width: 450px; text-align: center; }
        h1 { color: #4ade80; margin-bottom: 16px; }
        p { color: #aaa; margin-bottom: 24px; line-height: 1.5; }
        .btn { display: inline-block; padding: 12px 24px; background: rgba(255,255,255,0.08); color: #e8e8e8; border: 1px solid rgba(255,255,255,0.15); border-radius: 8px; text-decoration: none; }
    </style>
</head>
<body>
    <div class="card">
        <h1>)" +
           title + R"(</h1>
        <p>)" +
           message + R"(</p>
        <a href="/auth/login" class="btn">Return to Login</a>
    </div>
</body>
</html>)";
}
