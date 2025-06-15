<?php
require_once 'db_connect.php';
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $username = $_POST['username'];
    $password = password_hash($_POST['password'], PASSWORD_DEFAULT); //sifre gizleme
    $age = $_POST['age'];
    $gender = $_POST['gender'];
    try {
        $stmt = $pdo->prepare("INSERT INTO users (username, password, age, gender) VALUES (?, ?, ?, ?)");
        $stmt->execute([$username, $password, $age, $gender]);
        $success = "Başarıyla kayıt oldunuz $username";
        header("Location: login.php?success=" . urlencode($success));
        exit;
    } catch (PDOException $e) {
        $error = "Kayıt başarısız: " . $e->getMessage();
    }
}
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>Kayıt Ol</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h2>Kayıt Ol</h2>
        <?php if (isset($error)) echo "<div class='alert alert-danger'>$error</div>"; ?>
        <?php if (isset($success)) echo "<div class='alert alert-success'>$success</div>"; ?>
        <form method="post">
            <div class="mb-3">
                <label for="username" class="form-label">Kullanıcı Adı</label>
                <input type="text" class="form-control" id="username" name="username" required>
            </div>
            <div class="mb-3">
                <label for="password" class="form-label">Şifre</label>
                <input type="password" class="form-control" id="password" name="password" required>
            </div>
            <div class="mb-3">
                <label for="age" class="form-label">Yaş</label>
                <input type="number" class="form-control" id="age" name="age" min="1" max="120" required>
            </div>
            <div class="mb-3">
                <label for="gender" class="form-label">Cinsiyet</label>
                <select class="form-control" id="gender" name="gender" required>
                    <option value="Erkek">Erkek</option>
                    <option value="Kadın">Kadın</option>
                    <option value="Diğer">Diğer</option>
                </select>
            </div>
            <button type="submit" class="btn btn-primary">Kayıt Ol</button>
        </form>
        <p class="mt-3">Hesabınız var mı? <a href="login.php">Giriş Yap</a></p>
    </div>
</body>
</html>