diff --git a/lib/kadm5/Makefile.am b/lib/kadm5/Makefile.am
index de9a208..626b756 100644
--- a/lib/kadm5/Makefile.am
+++ b/lib/kadm5/Makefile.am
@@ -35,7 +35,7 @@ default_keys_SOURCES = default_keys.c
 kadm5includedir = $(includedir)/kadm5
 buildkadm5include = $(buildinclude)/kadm5
 
-dist_kadm5include_HEADERS = admin.h private.h kadm5-pwcheck.h
+dist_kadm5include_HEADERS = admin.h private.h kadm5-hook.h kadm5-pwcheck.h
 dist_kadm5include_HEADERS += $(srcdir)/kadm5-protos.h $(srcdir)/kadm5-private.h
 
 nodist_kadm5include_HEADERS = kadm5_err.h
@@ -108,6 +108,7 @@ dist_libkadm5srv_la_SOURCES =			\
 	randkey_s.c				\
 	rename_s.c				\
 	server_glue.c				\
+	server_hooks.c				\
 	setkey3_s.c				\
 	set_keys.c				\
 	set_modifier.c				\
diff --git a/lib/kadm5/chpass_s.c b/lib/kadm5/chpass_s.c
index d1ed732..5db70ae 100644
--- a/lib/kadm5/chpass_s.c
+++ b/lib/kadm5/chpass_s.c
@@ -50,6 +50,8 @@ change(void *server_handle,
     Key *keys;
     size_t num_keys;
     int existsp = 0;
+    int i;
+    krb5_error_code code;
 
     memset(&ent, 0, sizeof(ent));
     if (!context->keep_open) {
@@ -67,6 +69,22 @@ change(void *server_handle,
     if (ret)
 	goto out2;
 
+    for (i = 0; i < context->num_hooks; i++) {
+	kadm5_hook_context *hook = context->hooks[i];
+
+	if (hook->hook->chpass != NULL) {
+	    ret = hook->hook->chpass(context->context, hook->data,
+				     KADM5_HOOK_STAGE_PRECOMMIT,
+				     princ, password);
+	    if (ret != 0) {
+		krb5_set_error_message(context->context, ret,
+				       "password change hook `%s' failed"
+				       " precommit", hook->hook->name);
+		goto out3;
+	    }
+	}
+    }
+
     if (keepold || cond) {
 	
 	 * We save these for now so we can handle password history checking;
@@ -149,6 +167,19 @@ change(void *server_handle,
                            KADM5_KEY_DATA | KADM5_KVNO |
                            KADM5_PW_EXPIRATION | KADM5_TL_DATA);
 
+    for (i = 0; i < context->num_hooks; i++) {
+	kadm5_hook_context *hook = context->hooks[i];
+
+	if (hook->hook->chpass != NULL) {
+	    code = hook->hook->chpass(context->context, hook->data,
+				      KADM5_HOOK_STAGE_POSTCOMMIT,
+				      princ, password);
+	    if (code != 0)
+		krb5_warn(context->context, code, "password change hook `%s'"
+			  " failed postcommit", hook->hook->name);
+	}
+    }
+
  out3:
     hdb_free_entry(context->context, &ent);
  out2:
diff --git a/lib/kadm5/context_s.c b/lib/kadm5/context_s.c
index 4aeee5d..cf90e5f 100644
--- a/lib/kadm5/context_s.c
+++ b/lib/kadm5/context_s.c
@@ -268,6 +268,13 @@ _kadm5_s_init_context(kadm5_server_context **ctx,
 
     find_db_spec(*ctx);
 
+    ret = _kadm5_s_init_hooks(*ctx);
+    if (ret != 0) {
+	kadm5_s_destroy(*ctx);
+	*ctx = NULL;
+	return ret;
+    }
+

diff --git a/lib/kadm5/create_s.c b/lib/kadm5/create_s.c
index 7d8f898..8e1b924 100644
--- a/lib/kadm5/create_s.c
+++ b/lib/kadm5/create_s.c
@@ -171,6 +171,24 @@ kadm5_s_create_principal(void *server_handle,
     kadm5_ret_t ret;
     hdb_entry_ex ent;
     kadm5_server_context *context = server_handle;
+    int i;
+    krb5_error_code code;
+
+    for (i = 0; i < context->num_hooks; i++) {
+	kadm5_hook_context *hook = context->hooks[i];
+
+	if (hook->hook->create != NULL) {
+	    ret = hook->hook->create(context->context, hook->data,
+				     KADM5_HOOK_STAGE_PRECOMMIT, princ,
+				     mask, password);
+	    if (ret != 0) {
+		krb5_set_error_message(context->context, ret,
+				   "create hook `%s' failed precommit",
+				    hook->hook->name);
+		return ret;
+	    }
+	}
+    }
 
     if ((mask & KADM5_KVNO) == 0) {
 	/* create_principal() through _kadm5_setup_entry(), will need this */
@@ -214,6 +232,20 @@ kadm5_s_create_principal(void *server_handle,
     /* This logs the change for iprop and writes to the HDB */
     ret = kadm5_log_create(context, &ent.entry);
 
+    for (i = 0; i < context->num_hooks; i++) {
+	kadm5_hook_context *hook = context->hooks[i];
+
+	if (hook->hook->create != NULL) {
+	    code = hook->hook->create(context->context, hook->data,
+				      KADM5_HOOK_STAGE_POSTCOMMIT, princ,
+				      mask, password);
+	    if (code != 0)
+		krb5_warn(context->context, code,
+			  "create hook `%s' failed postcommit",
+			  hook->hook->name);
+	}
+    }
+
  out2:
     (void) kadm5_log_end(context);
  out:
diff --git a/lib/kadm5/destroy_s.c b/lib/kadm5/destroy_s.c
index 2424366..fc86e59 100644
--- a/lib/kadm5/destroy_s.c
+++ b/lib/kadm5/destroy_s.c
@@ -77,6 +77,7 @@ kadm5_s_destroy(void *server_handle)
     kadm5_server_context *context = server_handle;
     krb5_context kcontext = context->context;
 
+    _kadm5_s_free_hooks(context);
     if (context->db != NULL)
         ret = context->db->hdb_destroy(kcontext, context->db);
     destroy_kadm5_log_context(&context->log_context);
diff --git a/lib/kadm5/kadm5-hook.h b/lib/kadm5/kadm5-hook.h
new file mode 100644
index 0000000..faae19a
--- /dev/null
+++ b/lib/kadm5/kadm5-hook.h
@@ -0,0 +1,81 @@
+/*
+ * Copyright 2010
+ *     The Board of Trustees of the Leland Stanford Junior University
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions
+ * are met:
+ *
+ * 1. Redistributions of source code must retain the above copyright
+ *    notice, this list of conditions and the following disclaimer.
+ *
+ * 2. Redistributions in binary form must reproduce the above copyright
+ *    notice, this list of conditions and the following disclaimer in the
+ *    documentation and/or other materials provided with the distribution.
+ *
+ * 3. Neither the name of the Institute nor the names of its contributors
+ *    may be used to endorse or promote products derived from this software
+ *    without specific prior written permission.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
+ * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+ * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+ * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
+ * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
+ * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
+ * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+ * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
+ * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
+ * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
+ * SUCH DAMAGE.
+ */
+
+#ifndef KADM5_HOOK_H
+#define KADM5_HOOK_H 1
+
+#define KADM5_HOOK_VERSION_V0 0
+
+/*
+ * Each hook is called before the operation using KADM5_STAGE_PRECOMMIT and
+ * then after the operation using KADM5_STAGE_POSTCOMMIT.  If the hook returns
+ * failure during precommit, the operation is aborted without changes to the
+ * database.
+ */
+enum kadm5_hook_stage {
+    KADM5_HOOK_STAGE_PRECOMMIT,
+    KADM5_HOOK_STAGE_POSTCOMMIT
+};
+
+/*
+ * libkadm5srv expects a symbol named kadm5_hook_v0 exported by the dynamicaly
+ * loaded module and of type kadm5_hook.  version must be
+ * KADM5_HOOK_VERSION_V0.  Any or all of the function pointers may be NULL, in
+ * which case that hook will not be called.
+ */
+typedef struct kadm5_hook {
+    const char *name;
+    int version;
+    const char *vendor;
+
+    krb5_error_code (*init)(krb5_context, void **);
+    void (*fini)(krb5_context, void *);
+
+    krb5_error_code (*chpass)(krb5_context, void *, enum kadm5_hook_stage,
+			      krb5_principal, const char *);
+    krb5_error_code (*create)(krb5_context, void *, enum kadm5_hook_stage,
+			      kadm5_principal_ent_t, uint32_t mask,
+			      const char *password);
+    krb5_error_code (*modify)(krb5_context, void *, enum kadm5_hook_stage,
+			      kadm5_principal_ent_t, uint32_t mask);
+
+#if 0
+    krb5_error_code (*delete)(krb5_context, void *, enum kadm5_hook_stage,
+			      krb5_principal);
+    krb5_error_code (*randkey)(krb5_context, void *, enum kadm5_hook_stage,
+			       krb5_principal);
+    krb5_error_code (*rename)(krb5_context, void *, enum kadm5_hook_stage,
+			      krb5_principal source, krb5_principal target);
+#endif
+} kadm5_hook;
+
+#endif /* !KADM5_HOOK_H */
diff --git a/lib/kadm5/kadm5_err.et b/lib/kadm5/kadm5_err.et
index bcbaea8..1442919 100644
--- a/lib/kadm5/kadm5_err.et
+++ b/lib/kadm5/kadm5_err.et
@@ -67,3 +67,4 @@ error_code ALREADY_LOCKED,	"Database already locked"
 error_code NOT_LOCKED,		"Database not locked"
 error_code LOG_CORRUPT,		"Incremental propagation log got corrupted"
 error_code LOG_NEEDS_UPGRADE,	"Incremental propagation log must be upgraded"
+error_code BAD_SERVER_HOOK,	"Bad KADM5 server hook module"
diff --git a/lib/kadm5/modify_s.c b/lib/kadm5/modify_s.c
index 78f2673..b388693 100644
--- a/lib/kadm5/modify_s.c
+++ b/lib/kadm5/modify_s.c
@@ -44,6 +44,8 @@ modify_principal(void *server_handle,
     kadm5_server_context *context = server_handle;
     hdb_entry_ex ent;
     kadm5_ret_t ret;
+    int i;
+    krb5_error_code code;
 
     memset(&ent, 0, sizeof(ent));
 
@@ -66,6 +68,22 @@ modify_principal(void *server_handle,
 				      princ->principal, HDB_F_GET_ANY|HDB_F_ADMIN_DATA, 0, &ent);
     if (ret)
 	goto out2;
+    for (i = 0; i < context->num_hooks; i++) {
+	kadm5_hook_context *hook = context->hooks[i];
+
+	if (hook->hook->modify != NULL) {
+	    ret = hook->hook->modify(context->context, hook->data,
+				     KADM5_HOOK_STAGE_PRECOMMIT, princ,
+				     mask);
+	    if (ret != 0) {
+		krb5_set_error_message(context->context, code,
+				       "modify hook `%s' failed precommit",
+				       hook->hook->name);
+		goto out3;
+	    }
+	}
+    }
+
     ret = _kadm5_setup_entry(context, &ent, mask, princ, mask, NULL, 0);
     if (ret)
 	goto out3;
@@ -114,6 +132,20 @@ modify_principal(void *server_handle,
     ret = kadm5_log_modify(context, &ent.entry,
                            mask | KADM5_MOD_NAME | KADM5_MOD_TIME);
 
+    for (i = 0; i < context->num_hooks; i++) {
+	kadm5_hook_context *hook = context->hooks[i];
+
+	if (hook->hook->modify != NULL) {
+	    code = hook->hook->modify(context->context, hook->data,
+				      KADM5_HOOK_STAGE_POSTCOMMIT, princ,
+				      mask);
+	    if (code != 0)
+		krb5_warn(context->context, code,
+			  "modify hook `%s' failed postcommit",
+			   hook->hook->name);
+	}
+    }
+
  out3:
     hdb_free_entry(context->context, &ent);
  out2:
diff --git a/lib/kadm5/private.h b/lib/kadm5/private.h
index 0b14ebd..57ac19f 100644
--- a/lib/kadm5/private.h
+++ b/lib/kadm5/private.h
@@ -36,6 +36,8 @@
 #ifndef __kadm5_privatex_h__
 #define __kadm5_privatex_h__
 
+#include "kadm5-hook.h"
+
 #ifdef HAVE_SYS_UN_H
 #include <sys/un.h>
 #endif
@@ -67,6 +69,12 @@ struct kadm_func {
 				       krb5_keyblock *, int);
 };
 
+typedef struct kadm5_hook_context {
+    void *handle;
+    kadm5_hook *hook;
+    void *data;
+} kadm5_hook_context;
+
 /* XXX should be integrated */
 typedef struct kadm5_common_context {
     krb5_context context;
@@ -108,6 +116,8 @@ typedef struct kadm5_server_context {
     krb5_principal caller;
     unsigned acl_flags;
     kadm5_log_context log_context;
+    int num_hooks;
+    kadm5_hook_context **hooks;
 } kadm5_server_context;
 
 typedef struct kadm5_client_context {
diff --git a/lib/kadm5/server_hooks.c b/lib/kadm5/server_hooks.c
new file mode 100644
index 0000000..bf5ddfa
--- /dev/null
+++ b/lib/kadm5/server_hooks.c
@@ -0,0 +1,152 @@
+/*
+ * Copyright 2010
+ *     The Board of Trustees of the Leland Stanford Junior University
+ *
+ * Redistribution and use in source and binary forms, with or without
+ * modification, are permitted provided that the following conditions
+ * are met:
+ *
+ * 1. Redistributions of source code must retain the above copyright
+ *    notice, this list of conditions and the following disclaimer.
+ *
+ * 2. Redistributions in binary form must reproduce the above copyright
+ *    notice, this list of conditions and the following disclaimer in the
+ *    documentation and/or other materials provided with the distribution.
+ *
+ * 3. Neither the name of the Institute nor the names of its contributors
+ *    may be used to endorse or promote products derived from this software
+ *    without specific prior written permission.
+ *
+ * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
+ * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
+ * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
+ * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
+ * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
+ * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
+ * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
+ * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
+ * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
+ * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
+ * SUCH DAMAGE.
+ */
+
+#include "kadm5_locl.h"
+#include <dlfcn.h>
+
+#ifndef RTLD_NOW
+# define RTLD_NOW 0
+#endif
+
+/*
+ * Load kadmin server hooks.
+ */

+
+kadm5_ret_t
+_kadm5_s_init_hooks(kadm5_server_context *ctx)
+{
+    krb5_context context = ctx->context;
+    char **libraries;
+    const char *library;
+    int i;
+    void *handle = NULL;
+    struct kadm5_hook *hook;
+    struct kadm5_hook_context *hook_context = NULL;
+    struct kadm5_hook_context **tmp;
+    kadm5_ret_t ret = KADM5_BAD_SERVER_NAME;
+
+    libraries = krb5_config_get_strings(context, NULL,
+					"kadmin", "hook_libraries", NULL);
+    if (libraries == NULL)
+	return 0;
+    for (i = 0; libraries[i] != NULL; i++) {
+	library = libraries[i];
+	handle = dlopen(library, RTLD_NOW);
+	if (handle == NULL) {
+	    krb5_warnx(context, "failed to open `%s': %s", library, dlerror());
+	    goto fail;
+	}
+	hook = dlsym(handle, "kadm5_hook_v0");
+	if (hook == NULL) {
+	    krb5_warnx(context, "didn't find `kadm5_hook_v0' symbol in `%s':"
+		       " %s", library, dlerror());
+	    goto fail;
+	}
+	if (hook->version != KADM5_HOOK_VERSION_V0) {
+	    krb5_warnx(context, "version of loaded library `%s' is %d"
+		       " (expected %d)", library, hook->version,
+		       KADM5_HOOK_VERSION_V0);
+	    goto fail;
+	}
+	hook_context = malloc(sizeof(*hook_context));
+	if (hook_context == NULL) {
+	    krb5_warnx(context, "out of memory");
+	    ret = errno;
+	    goto fail;
+	}
+	hook_context->handle = handle;
+	hook_context->hook = hook;
+	if (hook->init == NULL) {
+	    hook_context->data = NULL;
+	} else {
+	    ret = hook->init(context, &hook_context->data);
+	    if (ret != 0) {
+		krb5_warn(context, ret, "initialization of `%s' failed",
+			  library);
+		goto fail;
+	    }
+	}
+	tmp = realloc(ctx->hooks, (ctx->num_hooks + 1) * sizeof(*tmp));
+	if (tmp == NULL) {
+	    krb5_warnx(context, "out of memory");
+	    ret = errno;
+	    goto fail;
+	}
+	ctx->hooks = tmp;
+	ctx->hooks[ctx->num_hooks] = hook_context;
+	hook_context = NULL;
+	ctx->num_hooks++;
+    }
+    return 0;
+
+fail:
+    _kadm5_s_free_hooks(ctx);
+    if (hook_context != NULL)
+	free(hook_context);
+    if (handle != NULL)
+	dlclose(handle);
+    return ret;
+}
+
+void
+_kadm5_s_free_hooks(kadm5_server_context *ctx)
+{
+    int i;
+    struct kadm5_hook *hook;
+
+    for (i = 0; i < ctx->num_hooks; i++) {
+	if (ctx->hooks[i]->hook->fini != NULL)
+	    ctx->hooks[i]->hook->fini(ctx->context, ctx->hooks[i]->data);
+	dlclose(ctx->hooks[i]->handle);
+	free(ctx->hooks[i]);
+    }
+    free(ctx->hooks);
+    ctx->hooks = NULL;
+    ctx->num_hooks = 0;
+}
+
+# else /* !HAVE_DLOPEN */
+
+kadm5_ret_t
+_kadm5_s_init_hooks(kadm5_server_context *ctx)
+{
+    return 0;
+}
+
+void
+_kadm5_s_free_hooks(kadm5_server_context *ctx)
+{
+    return 0;
+}
+
+#endif /* !HAVE_DLOPEN */