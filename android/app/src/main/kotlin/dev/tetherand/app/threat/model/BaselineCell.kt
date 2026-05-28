package dev.tetherand.app.threat.model

import androidx.room.ColumnInfo
import androidx.room.Dao
import androidx.room.Entity
import androidx.room.Index
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query

/**
 * One observation of a cell tower in a geohash6 location bucket.
 * The (geohash6, mccMnc, lac, cid) tuple is unique; upserts keep the
 * most-recent timestamp + signal and bump the sightings counter.
 */
@Entity(
    tableName = "baseline_cells",
    primaryKeys = ["geohash6", "mcc_mnc", "lac", "cid"],
    indices = [Index(value = ["geohash6"]), Index(value = ["mcc_mnc"])],
)
data class BaselineCell(
    @ColumnInfo(name = "geohash6") val geohash6: String,
    @ColumnInfo(name = "mcc_mnc")  val mccMnc: String,
    @ColumnInfo(name = "lac")      val lac: Int,
    @ColumnInfo(name = "cid")      val cid: Long,
    @ColumnInfo(name = "rat")      val rat: String,
    @ColumnInfo(name = "earfcn")   val earfcn: Int? = null,
    @ColumnInfo(name = "tac")      val tac: Int? = null,
    @ColumnInfo(name = "pci")      val pci: Int? = null,
    @ColumnInfo(name = "signal_dbm") val signalDbm: Int? = null,
    @ColumnInfo(name = "first_seen_ms") val firstSeenMs: Long,
    @ColumnInfo(name = "last_seen_ms")  val lastSeenMs: Long,
    @ColumnInfo(name = "sightings")     val sightings: Int = 1,
)

@Dao
interface BaselineCellDao {
    @Query("SELECT * FROM baseline_cells WHERE geohash6 = :geohash6")
    suspend fun forGeohash(geohash6: String): List<BaselineCell>

    @Query("""SELECT * FROM baseline_cells
              WHERE geohash6 = :geohash6 AND mcc_mnc = :mccMnc
                AND lac = :lac AND cid = :cid LIMIT 1""")
    suspend fun lookup(geohash6: String, mccMnc: String, lac: Int, cid: Long): BaselineCell?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(cell: BaselineCell)

    @Query("DELETE FROM baseline_cells WHERE last_seen_ms < :olderThanMs")
    suspend fun prune(olderThanMs: Long)
}
