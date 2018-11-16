/*
 * Copyright (C) the libgit2 contributors. All rights reserved.
 *
 * This file is part of libgit2, distributed under the GNU GPL v2 with
 * a Linking Exception. For full terms see the included COPYING file.
 */

#include "git2.h"
#include "smart.h"
#include "git2/cred_helpers.h"

static int git_cred_ssh_key_type_new(
	git_cred **cred,
	const char *username,
	const char *publickey,
	const char *privatekey,
	const char *passphrase,
	git_credtype_t credtype);

int git_cred_has_username(git_cred *cred)
{
	if (cred->credtype == GIT_CREDTYPE_DEFAULT)
		return 0;

	return 1;
}

const char *git_cred__username(git_cred *cred)
{
	switch (cred->credtype) {
	case GIT_CREDTYPE_USERNAME:
	{
		git_cred_username *c = (git_cred_username *) cred;
		return c->username;
	}
	case GIT_CREDTYPE_USERPASS_PLAINTEXT:
	{
		git_cred_userpass_plaintext *c = (git_cred_userpass_plaintext *) cred;
		return c->username;
	}
	case GIT_CREDTYPE_SSH_KEY:
	case GIT_CREDTYPE_SSH_MEMORY:
	{
		git_cred_ssh_key *c = (git_cred_ssh_key *) cred;
		return c->username;
	}

	default:
		return NULL;
	}
}

static void plaintext_free(struct git_cred *cred)
{
	git_cred_userpass_plaintext *c = (git_cred_userpass_plaintext *)cred;

	git__free(c->username);

	/* Zero the memory which previously held the password */
	if (c->password) {
		size_t pass_len = strlen(c->password);
		git__memzero(c->password, pass_len);
		git__free(c->password);
	}

	git__free(c);
}

int git_cred_userpass_plaintext_new(
	git_cred **cred,
	const char *username,
	const char *password)
{
	git_cred_userpass_plaintext *c;

	assert(cred && username && password);

	c = git__malloc(sizeof(git_cred_userpass_plaintext));
	GITERR_CHECK_ALLOC(c);

	c->parent.credtype = GIT_CREDTYPE_USERPASS_PLAINTEXT;
	c->parent.free = plaintext_free;
	c->username = git__strdup(username);

	if (!c->username) {
		git__free(c);
		return -1;
	}

	c->password = git__strdup(password);

	if (!c->password) {
		git__free(c->username);
		git__free(c);
		return -1;
	}

	*cred = &c->parent;
	return 0;
}

static void git__ssh_key_free(struct git_cred *cred)
{
	git_cred_ssh_key *c =
		(git_cred_ssh_key *)cred;

	git__free(c->username);

	if (c->privatekey) {
		/* Zero the memory which previously held the private key */
		size_t key_len = strlen(c->privatekey);
		git__memzero(c->privatekey, key_len);
		git__free(c->privatekey);
	}

	if (c->passphrase) {
		/* Zero the memory which previously held the passphrase */
		size_t pass_len = strlen(c->passphrase);
		git__memzero(c->passphrase, pass_len);
		git__free(c->passphrase);
	}

	if (c->publickey) {
		/* Zero the memory which previously held the public key */
		size_t key_len = strlen(c->publickey);
		git__memzero(c->publickey, key_len);
		git__free(c->publickey);
	}

	git__free(c);
}

static void default_free(struct git_cred *cred)
{
	git_cred_default *c = (git_cred_default *)cred;

	git__free(c);
}

static void username_free(struct git_cred *cred)
{
	git__free(cred);
}

int git_cred_ssh_key_new(
	git_cred **cred,
	const char *username,
	const char *publickey,
	const char *privatekey,
	const char *passphrase)
{
	return git_cred_ssh_key_type_new(
		cred,
		username,
		publickey,
		privatekey,
		passphrase,
		GIT_CREDTYPE_SSH_KEY);
}

int git_cred_ssh_key_memory_new(
	git_cred **cred,
	const char *username,
	const char *publickey,
	const char *privatekey,
	const char *passphrase)
{
#ifdef GIT_SSH_MEMORY_CREDENTIALS
	return git_cred_ssh_key_type_new(
		cred,
		username,
		publickey,
		privatekey,
		passphrase,
		GIT_CREDTYPE_SSH_MEMORY);
#else
	GIT_UNUSED(cred);
	GIT_UNUSED(username);
	GIT_UNUSED(publickey);
	GIT_UNUSED(privatekey);
	GIT_UNUSED(passphrase);

	giterr_set(GITERR_INVALID,
		"this version of libgit2 was not built with ssh memory credentials.");
	return -1;
#endif
}

static int git_cred_ssh_key_type_new(
	git_cred **cred,
	const char *username,
	const char *publickey,
	const char *privatekey,
	const char *passphrase,
	git_credtype_t credtype)
{
	git_cred_ssh_key *c;

	assert(username && cred && privatekey);

	c = git__calloc(1, sizeof(git_cred_ssh_key));
	GITERR_CHECK_ALLOC(c);

	c->parent.credtype = credtype;
	c->parent.free = git__ssh_key_free;

	c->username = git__strdup(username);
	GITERR_CHECK_ALLOC(c->username);

	c->privatekey = git__strdup(privatekey);
	GITERR_CHECK_ALLOC(c->privatekey);

	if (publickey) {
		c->publickey = git__strdup(publickey);
		GITERR_CHECK_ALLOC(c->publickey);
	}

	if (passphrase) {
		c->passphrase = git__strdup(passphrase);
		GITERR_CHECK_ALLOC(c->passphrase);
	}

	*cred = &c->parent;
	return 0;
}

int git_cred_ssh_key_from_agent(git_cred **cred, const char *username) {
	git_cred_ssh_key *c;

	assert(username && cred);

	c = git__calloc(1, sizeof(git_cred_ssh_key));
	GITERR_CHECK_ALLOC(c);

	c->parent.credtype = GIT_CREDTYPE_SSH_KEY;
	c->parent.free = git__ssh_key_free;

	c->username = git__strdup(username);
	GITERR_CHECK_ALLOC(c->username);

	c->privatekey = NULL;

	*cred = &c->parent;
	return 0;
}

int git_cred_default_new(git_cred **cred)
{
	git_cred_default *c;

	assert(cred);

	c = git__calloc(1, sizeof(git_cred_default));
	GITERR_CHECK_ALLOC(c);

	c->credtype = GIT_CREDTYPE_DEFAULT;
	c->free = default_free;

	*cred = c;
	return 0;
}

int git_cred_username_new(git_cred **cred, const char *username)
{
	git_cred_username *c;
	size_t len, allocsize;

	assert(cred);

	len = strlen(username);

	GITERR_CHECK_ALLOC_ADD(&allocsize, sizeof(git_cred_username), len);
	GITERR_CHECK_ALLOC_ADD(&allocsize, allocsize, 1);
	c = git__malloc(allocsize);
	GITERR_CHECK_ALLOC(c);

	c->parent.credtype = GIT_CREDTYPE_USERNAME;
	c->parent.free = username_free;
	memcpy(c->username, username, len + 1);

	*cred = (git_cred *) c;
	return 0;
}

void git_cred_free(git_cred *cred)
{
	if (!cred)
		return;

	cred->free(cred);
}
