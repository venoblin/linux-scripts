<br/>
<div align="center">
<a href="https://github.com/venoblin/scripts">
<img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAJ0AAACACAYAAAARbmuTAAAEFklEQVR4Xu3cP0gkVwDH8d9BCgsLCy0EC4VYBLwqIBYWWyhoKShYWNjlGkEhKYSEPUlxQgoVAloETKMWNhaCgkIsBFOkEBT8G7S0sNjCwsIivLkcXMh6Om/f/fB2vh8QYcGZ2ceX2Zk3b32l976W9E5SSVLzv68BqVQk/SXpJ0l/vpLUKOlIUnuqPQCPuJf0TYjuO0lLDBNMfgjR/SjpZ9MOgd9DdGVJbxkLmMwTHdyIDnZEBzuigx3RwY7oYEd0sIuPrq2tTaVSSZVKRZubm/YjxxcrLrqenh7t7OyosTE8tpW2t7c1MjKiu7u7L3YkYBMX3cHBQRbex/b39zU4OEh4eEpcdFdXV2pv//+iFMLDM8RFNzc3p8nJyarbJzw8IS66hoaG7Jqut7eX8JBXXHRB+Hgtl8saHx+vutOVlRXNzMzo4uIi70GhvsVH95zwVldXs/DOz8/rexiRR23RER4i1B7dc8JbW1vLznhnZ2cRx4g6kya6IEwUb21tPXpzsbe3p/7+fj08PNTZGCKndNE9J7zZ2VlNT0/nPEbUmbTRPfVRe3Jyou7ubp5aFFv66IKBgYHso7aa1tZW3dzcFHvYiy19dGHCOAT3YTHAxy4vL9XZ2VnsIUfa6MJEcZgwrvZc9vr6WhMTEyyDQrroPnWGC6ampjQ/P8+QI010nzrDheu3MEe3tMR/rkCm9ugIDjnVFh3BIUJ8dCmv4cKNR7Wbj7zC9zUODw/z/hm84qLr6urKlqxXmxbJc9MQQltcXMzm9VI5Pj7Oblp2d3dTbRJpxUUXFnD29fVVPZQ8d6nr6+saHh5O+5Yk3d7eqqWlJfl2kURcdI99RyJPcMHR0VF21vwcQnQhPrw4cdGFpUqjo6P/eTd5gwuWl5cfXXlcizAR3dHRUcsm8PnERdfc3Jw9eRgbG8su3BcWFrSxsZH7MJuamrKAU17TnZ6eamhoKPuNFykuutRCfOGnVvf39ywmePleRnQoFKKDHdHBjuhgR3SwIzrYER3siA52RAc7ooMd0cGO6GBHdLAjOtgRHeyIDnZEBzuigx3RwY7oYEd0sCM62BEd7IgOdkQHuyy6t5LK9l2jqIgOdkQHO6KDHdHBjuhgR3SwIzrYER3siA52RAc7ooMd0cGO6GBHdLAjOtgRHeyIDnZEBzuigx3RwY7oYEd0sCM62BEd7IgOdkQHO6KDHdHBjuhgR3SwIzrYER3siA52RAc7ooMd0cGO6GBHdLAjOtgRHeyIDnZEBzuigx3RwY7oYEd0sCM62BEd7IgOdkQHO6KDHdHBjuhgR3SwIzrYER3siA52RAc7ooNdFt33kn6x7xpF9VuIrk/STlFHAHYTIbrgD0kl++5RNNeSXn+I7itJbyR9W7RRgM3fkn6VVPkH4PXI3o5kwlQAAAAASUVORK5CYII=" alt="Termnial logo" />
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