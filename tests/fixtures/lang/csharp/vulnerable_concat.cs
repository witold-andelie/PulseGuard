using System.Data.SqlClient;
class Orders {
    void Order(SqlConnection conn) {
        var id = Request.Query["id"]; // @vuln SQL injection
        var query = "SELECT * FROM orders WHERE id = '" + id + "'";
        var cmd = new SqlCommand(query, conn);
        cmd.ExecuteReader();
    }
}
