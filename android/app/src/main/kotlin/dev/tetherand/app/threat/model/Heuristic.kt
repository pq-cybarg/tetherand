package dev.tetherand.app.threat.model

/** Stable identifiers for each heuristic. Never reorder; new heuristics append. */
enum class Heuristic {
    Bts_Algorithm,           // AIMSICD-derived
    Rat_Downgrade,           // SnoopSnitch-derived
    Tac_Change_No_Motion,    // Crocodile Hunter
    Earfcn_Out_Of_Range,     // Crocodile Hunter
    Reattach_Storm,          // Crocodile Hunter
    Evil_Twin_Wifi,          // ours
    Permission_Diff,         // ours
    Untrusted_Tracker_Ble,   // ours
}
