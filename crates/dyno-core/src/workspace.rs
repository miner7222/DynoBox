use std::path::{Path, PathBuf};

use crate::error::{DynoError, Result};

#[derive(Debug, Clone)]
pub struct Workspace {
    pub input_dir: PathBuf,
    pub output_dir: PathBuf,
}

impl Workspace {
    /// Creates a new Workspace, validating that the input directory exists.
    pub fn new(input: impl AsRef<Path>, output: impl AsRef<Path>) -> Result<Self> {
        let input_dir = input.as_ref().to_path_buf();
        let output_dir = output.as_ref().to_path_buf();

        if !input_dir.exists() {
            return Err(DynoError::MissingFile(format!(
                "Input directory does not exist: {}",
                input_dir.display()
            )));
        }

        if !input_dir.is_dir() {
            return Err(DynoError::Validation(format!(
                "Input path is not a directory: {}",
                input_dir.display()
            )));
        }

        Ok(Self {
            input_dir,
            output_dir,
        })
    }

    /// Creates the output directory and its parent components if they do not exist.
    pub fn prepare_output_dir(&self) -> Result<()> {
        if !self.output_dir.exists() {
            std::fs::create_dir_all(&self.output_dir)?;
        } else if !self.output_dir.is_dir() {
            return Err(DynoError::Validation(format!(
                "Output path exists but is not a directory: {}",
                self.output_dir.display()
            )));
        }
        Ok(())
    }

    /// Returns the absolute path to a file within the input directory.
    pub fn input_file(&self, name: &str) -> PathBuf {
        self.input_dir.join(name)
    }

    /// Returns the absolute path to a file within the output directory.
    pub fn output_file(&self, name: &str) -> PathBuf {
        self.output_dir.join(name)
    }
}
