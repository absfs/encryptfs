module github.com/absfs/encryptfs

go 1.24.0

require (
	github.com/absfs/absfs v0.0.0-20251208232938-aa0ca30de832
	github.com/absfs/memfs v0.0.0-20251123003602-523f8650011b
	github.com/google/uuid v1.6.0
	golang.org/x/crypto v0.45.0
)

require (
	github.com/absfs/inode v0.0.0-20251208170702-9db24ab95ae4 // indirect
	golang.org/x/sys v0.38.0 // indirect
)

replace (
	github.com/absfs/absfs => ../absfs
	github.com/absfs/fstools => ../fstools
	github.com/absfs/inode => ../inode
	github.com/absfs/memfs => ../memfs
)
