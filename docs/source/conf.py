# -- Project information -----------------------------------------------------
project = "nimvault"
copyright = "2025-2026, Rohit Goswami"
author = "Rohit Goswami"

# -- General configuration ---------------------------------------------------
extensions = [
    "sphinx.ext.intersphinx",
    "sphinx_sitemap",
]

templates_path = ["_templates"]
exclude_patterns = []

# -- Options for HTML output -------------------------------------------------
html_theme = "shibuya"
html_static_path = ["_static"]

html_context = {
    "source_type": "github",
    "source_user": "HaoZeke",
    "source_repo": "nimvault",
    "source_version": "main",
    "source_docs_path": "/docs/source/",
}

html_theme_options = {
    "github_url": "https://github.com/HaoZeke/nimvault",
    "accent_color": "teal",
    "dark_code": True,
    "globaltoc_expand_depth": 1,
    "nav_links": [
        {
            "title": "Nim API Docs",
            "url": "apidoc/nimvault.html",
        },
    ],
}

html_sidebars = {
    "**": [
        "sidebars/localtoc.html",
        "sidebars/repo-stats.html",
        "sidebars/edit-this-page.html",
    ],
}

html_baseurl = "nimvault.rgoswami.me"
