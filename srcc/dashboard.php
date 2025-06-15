<?php
session_start();
require_once 'db_connect.php';
require_once 'Portfolio.php';
if (!isset($_SESSION['user_id'])) {
    header("Location: login.php");
    exit;
}
$portfolio = new Portfolio($pdo);
$user_id = $_SESSION['user_id'];

// Kullanıcı bilgilerini al
$stmt = $pdo->prepare("SELECT username, age, gender FROM users WHERE id = ?");
$stmt->execute([$user_id]);
$user = $stmt->fetch(PDO::FETCH_ASSOC);

// Toplam kullanıcı sayısını al
$total_users_stmt = $pdo->query("SELECT COUNT(*) FROM users");
$total_users = $total_users_stmt->fetchColumn();

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['add'])) {
    $stock_name = $_POST['stock_name'];
    $quantity = $_POST['quantity'];
    $purchase_price = $_POST['purchase_price'];
    $purchase_date = $_POST['purchase_date'];
    $portfolio->addStock($user_id, $stock_name, $quantity, $purchase_price, $purchase_date);
}

if (isset($_GET['delete'])) {
    $portfolio->deleteStock($_GET['delete'], $user_id);
    header("Location: dashboard.php");
    exit;
}

if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['update'])) {
    $id = $_POST['id'];
    $stock_name = $_POST['stock_name'];
    $quantity = $_POST['quantity'];
    $purchase_price = $_POST['purchase_price'];
    $purchase_date = $_POST['purchase_date'];
    $portfolio->updateStock($id, $user_id, $stock_name, $quantity, $purchase_price, $purchase_date);
    header("Location: dashboard.php");
    exit;
}

$stocks = $portfolio->getStocks($user_id);
$edit_stock = null;
if (isset($_GET['edit'])) {
    $edit_stock = $portfolio->getStock($_GET['edit'], $user_id);
}
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>Kullanıcı Paneli</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <h2>Hoş geldin, <?php echo htmlspecialchars($user['username']); ?>!</h2>
        <h3 class="mt-5">Kullanıcı Bilgilerim</h3>
<table class="table table-striped">
    <thead>
        <tr>
            <th>Kullanıcı Adı</th>
            <th>Yaş</th>
            <th>Cinsiyet</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td><?php echo htmlspecialchars($user['username']); ?></td>
            <td><?php echo htmlspecialchars($user['age']); ?></td>
            <td><?php echo htmlspecialchars($user['gender']); ?></td>
        </tr>
    </tbody>
</table>
        <p><strong>Toplam Kullanıcı Sayısı:</strong> <?php echo htmlspecialchars($total_users); ?></p>
        <a href="logout.php" class="btn btn-danger mb-3">Çıkış Yap</a>
        <h3><?php echo $edit_stock ? 'Hisse Düzenle' : 'Yeni Hisse Ekle'; ?></h3>
        <form method="post">
            <?php if ($edit_stock) echo "<input type='hidden' name='id' value='{$edit_stock['id']}'>"; ?>
            <div class="mb-3">
                <label for="stock_name" class="form-label">Hisse Adı</label>
                <input type="text" class="form-control" id="stock_name" name="stock_name" value="<?php echo $edit_stock ? $edit_stock['stock_name'] : ''; ?>" required>
            </div>
            <div class="mb-3">
                <label for="quantity" class="form-label">Adet</label>
                <input type="number" class="form-control" id="quantity" name="quantity" value="<?php echo $edit_stock ? $edit_stock['quantity'] : ''; ?>" required>
            </div>
            <div class="mb-3">
                <label for="purchase_price" class="form-label">Alış Fiyatı</label>
                <input type="number" step="0.01" class="form-control" id="purchase_price" name="purchase_price" value="<?php echo $edit_stock ? $edit_stock['purchase_price'] : ''; ?>" required>
            </div>
            <div class="mb-3">
                <label for="purchase_date" class="form-label">Alış Tarihi</label>
                <input type="date" class="form-control" id="purchase_date" name="purchase_date" value="<?php echo $edit_stock ? $edit_stock['purchase_date'] : ''; ?>" required>
            </div>
            <button type="submit" name="<?php echo $edit_stock ? 'update' : 'add'; ?>" class="btn btn-primary"><?php echo $edit_stock ? 'Güncelle' : 'Ekle'; ?></button>
        </form>
        <h3 class="mt-5">Portföyüm</h3>
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>Hisse Adı</th>
                    <th>Adet</th>
                    <th>Alış Fiyatı</th>
                    <th>Alış Tarihi</th>
                    <th>İşlemler</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($stocks as $stock): ?>
                <tr>
                    <td><?php echo htmlspecialchars($stock['stock_name']); ?></td>
                    <td><?php echo $stock['quantity']; ?></td>
                    <td><?php echo $stock['purchase_price']; ?></td>
                    <td><?php echo $stock['purchase_date']; ?></td>
                    <td>
                        <a href="?edit=<?php echo $stock['id']; ?>" class="btn btn-sm btn-warning">Düzenle</a>
                        <a href="?delete=<?php echo $stock['id']; ?>" class="btn btn-sm btn-danger" onclick="return confirm('Silmek istediğinize emin misiniz?');">Sil</a>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</body>
</html>