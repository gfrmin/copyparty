# copyparty JSON API v1

Zero-build API for independent client development.

## Base URL

All endpoints are at `/.cpr/api/v1/`

## Response Format

### Success
```json
{
  "ok": true,
  "data": {}
}
```

### Error
```json
{
  "ok": false,
  "error": "error message",
  "code": 400
}
```

## Configuration Endpoints

### GET /config

Server configuration and features.

**Response:**
```json
{
  "ok": true,
  "data": {
    "version": "1.20.6",
    "name": "my-server",
    "features": {
      "up2k": true,
      "thumbnails": false,
      "search": true,
      "mediakeys": false
    }
  }
}
```

### GET /session

Current user session and permissions.

**Response:**
```json
{
  "ok": true,
  "data": {
    "user": "*",
    "authenticated": false,
    "permissions": null,
    "volumes": []
  }
}
```

## File Operations

### GET /browse

List directory contents.

**Query Parameters:**
- `path` (optional): Directory path (defaults to "/")

**Response:**
```json
{
  "ok": true,
  "data": {
    "path": "/",
    "breadcrumbs": [
      {"path": "docs", "name": "docs"}
    ],
    "items": [
      {
        "name": "file.txt",
        "type": "file",
        "size": 1024,
        "modified": "2026-02-04T12:00:00+00:00",
        "ext": "txt"
      }
    ],
    "stats": {
      "count": 1,
      "can_write": false
    }
  }
}
```

### POST /files/mkdir

Create a directory.

**Request:**
```json
{
  "path": "/parent",
  "name": "newdir"
}
```

**Response:**
```json
{
  "ok": true,
  "data": {
    "path": "/parent/newdir",
    "name": "newdir"
  }
}
```

### POST /files/move

Move or rename files.

**Request:**
```json
{
  "source": "/old/path",
  "destination": "/new/path",
  "overwrite": false
}
```

**Response:**
```json
{
  "ok": true,
  "data": {
    "source": "/old/path",
    "destination": "/new/path",
    "status": null
  }
}
```

### POST /files/delete

Delete files or directories.

**Request:**
```json
{
  "paths": ["/file1", "/file2"]
}
```

**Response:**
```json
{
  "ok": true,
  "data": {
    "deleted": 2,
    "status": null
  }
}
```

### POST /files/rename

Rename a file.

**Request:**
```json
{
  "path": "/old/name",
  "name": "newname"
}
```

**Response:**
```json
{
  "ok": true,
  "data": {
    "source": "/old/name",
    "destination": "/old/newname",
    "status": null
  }
}
```

## Authentication

### POST /auth/login

Authenticate with password.

**Request:**
```json
{
  "password": "mypassword",
  "username": "alice"
}
```

**Response:**
```json
{
  "ok": true,
  "data": {
    "user": "alice",
    "authenticated": true
  }
}
```

### POST /auth/logout

End user session.

**Response:**
```json
{
  "ok": true,
  "data": {
    "status": "logged out",
    "user": "alice"
  }
}
```

### POST /auth/chpw

Change user password.

**Request:**
```json
{
  "old_password": "current",
  "new_password": "newpass"
}
```

**Response:**
```json
{
  "ok": true,
  "data": {
    "status": "password changed",
    "user": "alice"
  }
}
```

## Search

### POST /search

Search for files.

**Request:**
```json
{
  "query": "*.pdf",
  "path": "/docs"
}
```

**Response:**
```json
{
  "ok": true,
  "data": {
    "query": "*.pdf",
    "path": "/docs",
    "results": [],
    "count": 0
  }
}
```

### GET /tags

Get tags for a file.

**Query Parameters:**
- `path` (required): File path

**Response:**
```json
{
  "ok": true,
  "data": {
    "path": "/file.txt",
    "tags": []
  }
}
```

## Upload

### POST /upload/init

Initiate upload session.

**Request:**
```json
{
  "path": "/destination"
}
```

**Response:**
```json
{
  "ok": true,
  "data": {
    "path": "/destination",
    "status": "ready",
    "user": "alice"
  }
}
```

### POST /upload/finalize

Complete upload.

**Request:**
```json
{
  "path": "/file"
}
```

**Response:**
```json
{
  "ok": true,
  "data": {
    "path": "/file",
    "status": "complete",
    "user": "alice"
  }
}
```

## Error Codes

- `400` - Bad request (invalid parameters)
- `401` - Unauthorized (authentication required)
- `403` - Forbidden (permission denied)
- `404` - Not found
- `405` - Method not allowed
- `422` - Unprocessable entity (validation error)
- `500` - Internal server error
- `503` - Service unavailable

## Client Example

```javascript
// Fetch config
const config = await fetch('/.cpr/api/v1/config').then(r => r.json());
console.log(config.data.version);

// Browse directory
const listing = await fetch('/.cpr/api/v1/browse?path=/').then(r => r.json());
console.log(listing.data.items);

// Create directory
const result = await fetch('/.cpr/api/v1/files/mkdir', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ path: '/', name: 'mydir' })
}).then(r => r.json());

if (result.ok) {
  console.log('Created:', result.data.path);
}
```
