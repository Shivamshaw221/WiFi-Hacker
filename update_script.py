import os
import subprocess

def update_project():
    """
    Pull the latest changes from the GitHub repository.
    """
    try:
        # Change directory to the project's directory
        project_path = os.path.dirname(os.path.abspath(__file__))
        os.chdir(project_path)

        # Pull the latest changes from the main branch
        subprocess.run(["git", "pull", "origin", "main"], check=True)
        print("Project updated successfully!")

    except subprocess.CalledProcessError as e:
        print(f"An error occurred while updating the project: {e}")

def update_dependencies():
    """
    Update the dependencies listed in requirements.txt.
    """
    try:
        # Path to the requirements.txt file
        requirements_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "requirements.txt")

        # Update dependencies
        subprocess.run(["pip", "install", "--upgrade", "-r", requirements_path], check=True)
        print("Dependencies updated successfully!")

    except subprocess.CalledProcessError as e:
        print(f"An error occurred while updating dependencies: {e}")

def main():
    """
    Main function to update the project and dependencies.
    """
    print("Starting update process...")
    
    update_project()
    update_dependencies()
    
    print("Update process completed!")

if __name__ == "__main__":
    main()
