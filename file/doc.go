// Copyright 2026 AxonOps Limited.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package file provides a file-based [audit.Output] implementation with
// automatic size-based rotation, backup retention, age-based cleanup,
// and optional gzip compression.
//
// # Construction
//
// Create a file output with [New]:
//
//	out, err := file.New(file.Config{
//	    Path:       "/var/log/audit/events.log",
//	    MaxSizeMB:  100,
//	    MaxBackups: 5,
//	    MaxAgeDays: 30,
//	}, nil) // optional file.Metrics
//
// The parent directory of [Config.Path] must exist before calling [New];
// the file itself is created if it does not exist. Default permissions
// are 0600.
//
// # Rotation
//
// When the active log file exceeds [Config.MaxSizeMB], it is renamed
// with a timestamp suffix and a new file is opened. Old backups are
// pruned by count ([Config.MaxBackups]) and age ([Config.MaxAgeDays]).
// Compressed backups use gzip (enabled by default).
//
// Recommended import alias:
//
//	import auditfile "github.com/axonops/audit/file"
package file
