<?php
session_start();
if (isset($_SESSION['user_id'])) {
    header("Location: dashboard.php");
    exit;
}
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>Koçepe Borsa Yatırım Takip Sistemi</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h1 class="text-center">Koçepe Borsa Yatırım Takip Sistemi</h1>
        <div class="text-center mt-4">
            <a href="register.php" class="btn btn-primary">Kayıt Ol</a>
            <a href="login.php" class="btn btn-secondary">Giriş Yap</a>
        </div>
    </div>
</body>
</html>