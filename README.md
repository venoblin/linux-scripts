<br/>
<div align="center">
<a href="https://github.com/venoblin/scripts">
<img src=".project-images/project-logo.png" alt="Termnial logo" height="128px" />
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
# opens vs code with disabled gpu
ezcode

# initializes cpp project at current working directory
ezcppinit

# sorts download folder
ezdownloadsorter

# pulls from current Git branch
ezgitpull

# pushes to current Git branch
ezgitpush "commit message"

# starts kwin's logger for debugging purposes
ezkwinlog

# creates directory containing JavaScript(jsx) or TypeScript(tsx) React component
# with a corresponding SCSS file, if no type is specified as the second argument
# then JavaScript(jsx) will be used
ezreactcmpntinit ./project/components/NewComponentName tsx

# initializes readme template at current working directory
ezreadmeinit

# updates Linux system (supports dnf, zypper, and apt)
ezupdate

# sets up git
ezgitsetup

# sets up zsh and Oh My Zsh
ezzshsetup

# turns all scripts to binary files
ezshc
```

### Built With

This project was built with the following technologies:

- <img src="https://img.shields.io/badge/Bash-4EAA25?logo=gnubash&logoColor=fff" alt="Bash" />
- <img src="https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=fff" alt="Python" />

## Getting Started

Current scripts are used in a Linux enviroment using `zypper`, `dnf`, or `apt` package managers. Modification might be necessary for them to work in other systems.


### Installation

1. **Clone the repository** 

  ```sh
  git clone --recurse-submodules https://github.com/venoblin/scripts
  ```

2. **Create `settings.json` file in project root directory (for [ezdownloadsorter](https://github.com/venoblin/download-file-sorter))**

  ```sh
  cd scripts
  touch settings.json
  ```

3. **Modify `settings.json`** 

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