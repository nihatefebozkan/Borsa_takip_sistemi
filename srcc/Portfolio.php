<?php
class Portfolio {
    private $pdo;

    public function __construct($pdo) {
        $this->pdo = $pdo;
    }

    public function addStock($user_id, $stock_name, $quantity, $purchase_price, $purchase_date) {
        $stmt = $this->pdo->prepare("INSERT INTO portfolio (user_id, stock_name, quantity, purchase_price, purchase_date) VALUES (?, ?, ?, ?, ?)");
        return $stmt->execute([$user_id, $stock_name, $quantity, $purchase_price, $purchase_date]);
    }

    public function getStocks($user_id) {
        $stmt = $this->pdo->prepare("SELECT * FROM portfolio WHERE user_id = ?");
        $stmt->execute([$user_id]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function getStock($id, $user_id) {
        $stmt = $this->pdo->prepare("SELECT * FROM portfolio WHERE id = ? AND user_id = ?");
        $stmt->execute([$id, $user_id]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    public function updateStock($id, $user_id, $stock_name, $quantity, $purchase_price, $purchase_date) {
        $stmt = $this->pdo->prepare("UPDATE portfolio SET stock_name = ?, quantity = ?, purchase_price = ?, purchase_date = ? WHERE id = ? AND user_id = ?");
        return $stmt->execute([$stock_name, $quantity, $purchase_price, $purchase_date, $id, $user_id]);
    }

    public function deleteStock($id, $user_id) {
        $stmt = $this->pdo->prepare("DELETE FROM portfolio WHERE id = ? AND user_id = ?");
        return $stmt->execute([$id, $user_id]);
    }
}
?>