using System.Data.SqlClient;
class Orders {
    void Update(SqlConnection conn) {
        var owner = Request.Form["owner"];
        var cmd = new SqlCommand();
        cmd.Connection = conn;
        cmd.CommandText = "DELETE FROM orders WHERE owner = '" + owner + "'";
        cmd.ExecuteNonQuery();
    }
}
