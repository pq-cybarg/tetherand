package dev.tetherand.app.threat.model

import androidx.room.ColumnInfo
import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.PrimaryKey
import androidx.room.Query
import kotlinx.coroutines.flow.Flow

@Entity(tableName = "alerts")
data class Alert(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    @ColumnInfo(name = "ts_ms")        val tsMs: Long,
    @ColumnInfo(name = "heuristic")    val heuristic: Heuristic,
    @ColumnInfo(name = "severity")     val severity: Severity,
    @ColumnInfo(name = "summary")      val summary: String,
    @ColumnInfo(name = "evidence_json") val evidenceJson: String,
    @ColumnInfo(name = "geohash6")     val geohash6: String?,
    @ColumnInfo(name = "dismissed")    val dismissed: Boolean = false,
)

@Dao
interface AlertDao {
    @Insert
    suspend fun insert(alert: Alert): Long

    @Query("SELECT * FROM alerts WHERE dismissed = 0 ORDER BY ts_ms DESC LIMIT :limit")
    fun observeRecent(limit: Int = 50): Flow<List<Alert>>

    @Query("UPDATE alerts SET dismissed = 1 WHERE id = :id")
    suspend fun dismiss(id: Long)

    @Query("DELETE FROM alerts WHERE ts_ms < :olderThanMs")
    suspend fun prune(olderThanMs: Long)

    @Query("SELECT COUNT(*) FROM alerts WHERE ts_ms >= :sinceMs AND dismissed = 0")
    suspend fun countSince(sinceMs: Long): Int

    @Query("SELECT severity FROM alerts WHERE ts_ms >= :sinceMs AND dismissed = 0")
    suspend fun severitiesSince(sinceMs: Long): List<Severity>
}
