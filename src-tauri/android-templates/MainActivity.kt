package com.voidechoes7.cipherpass

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.DocumentsContract
import android.provider.Settings
import android.webkit.JavascriptInterface
import android.webkit.WebView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import org.json.JSONObject

class MainActivity : TauriActivity() {
  private var appWebView: WebView? = null
  private var pendingFileName: String = "CipherPass_Vault.kdbx"

  private val openDocumentTreeLauncher = registerForActivityResult(
    ActivityResultContracts.OpenDocumentTree()
  ) { treeUri: Uri? ->
    if (treeUri == null) {
      dispatchFolderPicked(null, null)
      return@registerForActivityResult
    }
    try {
      val flags =
        Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
      try {
        contentResolver.takePersistableUriPermission(treeUri, flags)
      } catch (_: SecurityException) {
        // Some document providers do not support persistable permissions; continue with temporary grant.
      }

      val cleanName = sanitizeFileName(pendingFileName)

      // 1. If All Files Access is granted and the user picked a folder on primary storage,
      //    resolve it to a direct /storage/emulated/0/... path for full atomic Rust I/O.
      val resolvedPath = tryResolvePrimaryStoragePath(treeUri)
      if (resolvedPath != null && hasAllFilesAccessInternal()) {
        val fullPath = resolvedPath.trimEnd('/') + "/" + cleanName
        dispatchFolderPicked(fullPath, null)
        return@registerForActivityResult
      }

      // 2. Otherwise, create the target .kdbx document inside the SAF tree URI so tauri-plugin-fs
      //    can write and read it via content:// even without MANAGE_EXTERNAL_STORAGE.
      val treeDocId = DocumentsContract.getTreeDocumentId(treeUri)
      val parentDocUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, treeDocId)
      val createdUri = DocumentsContract.createDocument(
        contentResolver,
        parentDocUri,
        "application/octet-stream",
        cleanName
      )
      if (createdUri != null) {
        dispatchFolderPicked(createdUri.toString(), null)
      } else {
        dispatchFolderPicked(null, "Could not create $cleanName in the selected folder.")
      }
    } catch (e: Exception) {
      dispatchFolderPicked(null, e.message ?: "Failed to access selected folder.")
    }
  }

  override fun onWebViewCreate(webView: WebView) {
    super.onWebViewCreate(webView)
    appWebView = webView
    webView.addJavascriptInterface(AndroidStorageBridge(), "CipherPassAndroid")
  }

  override fun onResume() {
    super.onResume()
    val granted = hasAllFilesAccessInternal()
    appWebView?.post {
      appWebView?.evaluateJavascript(
        "window.dispatchEvent(new CustomEvent('cipherpass-storage-permission-changed', { detail: { granted: $granted } }));",
        null
      )
    }
  }

  private fun hasAllFilesAccessInternal(): Boolean {
    return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
      Environment.isExternalStorageManager()
    } else {
      ContextCompat.checkSelfPermission(
        this,
        Manifest.permission.WRITE_EXTERNAL_STORAGE
      ) == PackageManager.PERMISSION_GRANTED
    }
  }

  private fun sanitizeFileName(raw: String): String {
    val trimmed = raw.trim().replace("/", "_").replace("\\", "_")
    val base = if (trimmed.isEmpty()) "CipherPass_Vault.kdbx" else trimmed
    return if (base.endsWith(".kdbx", ignoreCase = true)) base else "$base.kdbx"
  }

  private fun tryResolvePrimaryStoragePath(treeUri: Uri): String? {
    if (treeUri.authority != "com.android.externalstorage.documents") return null
    val docId = try {
      DocumentsContract.getTreeDocumentId(treeUri)
    } catch (_: Exception) {
      return null
    } ?: return null
    val parts = docId.split(":", limit = 2)
    if (parts.size != 2 || !parts[0].equals("primary", ignoreCase = true)) return null
    val rel = parts[1].trim('/')
    val base = Environment.getExternalStorageDirectory().absolutePath.trimEnd('/')
    return if (rel.isEmpty()) base else "$base/$rel"
  }

  private fun dispatchFolderPicked(path: String?, error: String?) {
    val payload = JSONObject()
    if (path != null) payload.put("path", path) else payload.put("path", JSONObject.NULL)
    if (error != null) payload.put("error", error) else payload.put("error", JSONObject.NULL)
    val js =
      "window.dispatchEvent(new CustomEvent('cipherpass-native-folder-picked', { detail: $payload }));"
    appWebView?.post {
      appWebView?.evaluateJavascript(js, null)
    }
  }

  inner class AndroidStorageBridge {
    @JavascriptInterface
    fun hasAllFilesAccess(): Boolean {
      return hasAllFilesAccessInternal()
    }

    @JavascriptInterface
    fun requestAllFilesAccess(): Boolean {
      return try {
        runOnUiThread {
          if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            try {
              val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION)
              intent.data = Uri.parse("package:$packageName")
              startActivity(intent)
            } catch (_: Exception) {
              val fallback = Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)
              startActivity(fallback)
            }
          } else {
            ActivityCompat.requestPermissions(
              this@MainActivity,
              arrayOf(
                Manifest.permission.READ_EXTERNAL_STORAGE,
                Manifest.permission.WRITE_EXTERNAL_STORAGE
              ),
              1001
            )
          }
        }
        true
      } catch (_: Exception) {
        false
      }
    }

    @JavascriptInterface
    fun pickNativeFolder(defaultFileName: String): Boolean {
      return try {
        pendingFileName = defaultFileName
        runOnUiThread {
          openDocumentTreeLauncher.launch(null)
        }
        true
      } catch (_: Exception) {
        false
      }
    }
  }
}
