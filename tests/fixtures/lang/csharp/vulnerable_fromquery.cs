using System.Data.SqlClient;
class Orders {
    void Order([FromQuery] string id, SqlConnection conn) {
        var cmd = new SqlCommand("SELECT * FROM orders WHERE id = '" + id + "'", conn);
        cmd.ExecuteReader();
    }
}
