# chameleon
## Functions
Encrypt and decrypt files using AES/GCM 256bit.

Hidden Metadata
- directory structure
- file names
- directory names
- filename to content association

Exposed Metadata
- number of files
- filesize

### Example

Before
```
sussy-data
├── sussy-dir1
│   ├── sussy-dir1.1
│   │   ├── sussy-file1
│   │   └── sussy-file2
│   └── sussy-dir1.2
│       ├── sussy-file1
│       ├── sussy-file2
│       └── sussy-file3
├── sussy-dir2
│   ├── sussy-file1
│   └── sussy-file2
└── sussy-dir3
```

After
```
output
├── 35b915320b28b582935f67ac801b391328b9da781fea4fd4473d57ce2ae85f28
├── 7d9892a93f4c9498ff911ec34cf03e5a2178b5266a5ff0e82c519dcb31d732af
├── 7fdc624a6e690ae5f8616207bf12c2da86928fc4dcce6deef8493e82a9bf6776
├── 88317c689ff2839d9631de1e06a61070291f6db66447c7feeb6f810158eca743
├── a3181092f9f963d94e664963e1faf75883a197ef48d6f2b5036238f684246408
├── c6f2abfb20cd0c1a65772ce8b2c345670a1745815d0da8b9cfd080fde941abd9
├── f9df9ac538cf4da68f9dd82a70de81e362ad8b36b0ef8715827801f1acc39527
└── index
```

## Installation
```
git clone https://github.com/elias-boemeke/chameleon.git
cd chameleon
go build
./chameleon
```

## Usage
```
Usage:
        encrypt FILES (file or directory) and save encrypted content in TDIR
        $ chameleon -e FILES TDIR

        list encrypted files in DIR by number
        $ chameleon -l DIR

        decrypt directory DIR; optionally select only specific files with the selection pattern
        pattern: \d+(-\d+)?(,\d+(-\d+)?)*  ;  i.e. '5,7-12,17'
        $ chameleon -d DIR [-p SP]
```

