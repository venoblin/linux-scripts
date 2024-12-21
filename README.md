<br/>
<div align="center">
<a href="https://github.com/venoblin/scripts">
<img src=".project-images/project-logo.png" alt="Termnial logo" />
</a>

<h3 align="center">Scripts</h3>
<p align="center">
Scripts to make your life easier!
<br/>
<br/>
</p>
</div>

Table of Contents

- [About The Project](#about-the-project)
  - [Scripts](#scripts)
  - [Built With](#built-with)
- [Getting Started](#getting-started)
  - [Installation](#installation)

## About The Project

### Scripts

```sh
ezcode
# opens vs code with disabled gpu

ezcppinit
# initializes cpp project

ezdownloadsorter
# sorts download folder

ezgitpull
# pulls current branch

ezgitpush
# pushes to current branch

ezkwinlog
# starts kwin's logger for debugging purposes

ezreactcmpntinit
# initializes react component directory

ezreadmeinit
# initializes readme template

ezupdate
# updates Linux system (supports dnf, zypper, and apt)

ezgitsetup
# sets up git

ezshc
# turns all scripts to binary

ezzshsetup
# sets up zsh and on my zsh
```

### Built With

This project was built with the following technologies:

- <img src="https://img.shields.io/badge/Bash-4EAA25?style=for-the-badge&logo=gnubash&logoColor=white" alt="Bash" />
- <img src="https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54" alt="Python" />

## Getting Started

Current scripts are used in an Linux enviroment using `zypper`, `dnf`, or `apt` package managers. Modification might be necessary for them to work in other systems.


### Installation

1. **Clone the repository** 

  ```sh
  git clone --recurse-submodules https://github.com/venoblin/scripts
  ```

2. **Create settings file (for [ezdownloadsorter](https://github.com/venoblin/download-file-sorter))**

  ```sh
  cd scripts
  touch settings.json
  ```

1. **Modify `settings.json`** 

  ```json
  {
    "downloads": "/path/to/Downloads",
    "destinations": {
      ".file-extension": "/path/to/destination",
      ".file-extension": "/path/to/destination",
      ".file-extension": "/path/to/destination"
    }
  }
  ```

4. **Install scripts** 
  
  ```sh
  ./install.sh
  ```