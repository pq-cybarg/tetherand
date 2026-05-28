package dev.tetherand.app.aiguard.runtime

/**
 * The 4-model bundle catalogue. Ships ABSENT in this milestone — models
 * are delivered through the M10.x in-APK delta-update mechanism, signed
 * via cosign against a pinned public key. Until then every classifier
 * falls back to the deterministic primary per spec.
 *
 * Each entry is the asset-relative path inside the APK and the expected
 * SHA-256 of the model file. Loaders verify the hash before mapping.
 */
object ModelBundle {

    data class Model(
        val id: String,
        val assetPath: String,
        val sha256Hex: String,
        val sizeMb: Int,
    )

    val PHI_TETHERAND = Model(
        id = "phi-tetherand-3b-q4",
        assetPath = "aiguard/phi-tetherand-3b-q4.tflite",
        sha256Hex = "TBD-cosign-pinned",
        sizeMb = 1800,
    )
    val VOICEGUARD = Model(
        id = "voiceguard-v1",
        assetPath = "aiguard/voiceguard-v1.tflite",
        sha256Hex = "TBD-cosign-pinned",
        sizeMb = 30,
    )
    val TEXTGUARD = Model(
        id = "textguard-v1",
        assetPath = "aiguard/textguard-v1.tflite",
        sha256Hex = "TBD-cosign-pinned",
        sizeMb = 20,
    )
    val QRGUARD = Model(
        id = "qrguard-v1",
        assetPath = "aiguard/qrguard-v1.tflite",
        sha256Hex = "TBD-cosign-pinned",
        sizeMb = 8,
    )

    val ALL: List<Model> = listOf(PHI_TETHERAND, VOICEGUARD, TEXTGUARD, QRGUARD)
}
