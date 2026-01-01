package dev.tetherand.app.threat.model

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverter
import androidx.room.TypeConverters

class Converters {
    @TypeConverter fun heuristicFromString(value: String): Heuristic = Heuristic.valueOf(value)
    @TypeConverter fun heuristicToString(value: Heuristic): String = value.name
    @TypeConverter fun severityFromString(value: String): Severity = Severity.valueOf(value)
    @TypeConverter fun severityToString(value: Severity): String = value.name
}

@Database(
    entities = [Alert::class, BaselineCell::class],
    version = 1,
    exportSchema = true,
)
@TypeConverters(Converters::class)
abstract class ThreatDb : RoomDatabase() {
    abstract fun alerts(): AlertDao
    abstract fun baselineCells(): BaselineCellDao

    companion object {
        @Volatile private var INSTANCE: ThreatDb? = null

        fun get(ctx: Context): ThreatDb = INSTANCE ?: synchronized(this) {
            INSTANCE ?: Room.databaseBuilder(
                ctx.applicationContext,
                ThreatDb::class.java,
                "tetherand-threat.db",
            ).build().also { INSTANCE = it }
        }
    }
}
