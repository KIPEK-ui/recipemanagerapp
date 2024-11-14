function previewImage(event) {
    const preview = document.getElementById('preview');
    preview.src = URL.createObjectURL(event.target.files[0]);
    preview.style.display = 'block'; // Show the preview image
}

function previewUpdateImage(event) {
    const preview = document.getElementById('updatePreview');
    preview.src = URL.createObjectURL(event.target.files[0]);
    preview.style.display = 'block'; // Show the preview image
}

$(document).ready(function() {
    // Handle form submission
    $('#insertForm').on('submit', function(event) {
        event.preventDefault();
        const formData = new FormData(this);

        $.ajax({
            url: '/insert',
            type: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            success: function(response) {
                alert('Recipe inserted successfully!');
                $('#insertModal').modal('hide');
                fetchRecipes();
            },
            error: function() {
                alert('Error inserting recipe.');
            }
        });
    });

    // Handle update form submission
    $('#updateForm').on('submit', function(event) {
        event.preventDefault();
        const id = $('#updateId').val();
        const formData = new FormData(this);

        $.ajax({
            url: `/update/${id}`,
            type: 'POST',
            data: formData,
            processData: false,
            contentType: false,
            success: function(response) {
                alert('Recipe updated successfully!');
                $('#updateModal').modal('hide');
                fetchRecipes();
            },
            error: function() {
                alert('Error updating recipe.');
            }
        });
    });

    // Fetch all recipes
    function fetchRecipes() {
        $.ajax({
            url: '/recipes',
            type: 'GET',
            success: function(data) {
                const recipeList = $('#recipeList');
                recipeList.empty(); // Clear existing recipes
                const template = document.getElementById('recipeCardTemplate').content;

                data.forEach(recipe => {
                    const clone = document.importNode(template, true);
                    clone.querySelector('.card-img-top').src = `/uploads/${recipe.image}`;
                    clone.querySelector('.card-img-top').alt = recipe.name;
                    clone.querySelector('.card-title').textContent = recipe.name;
                    clone.querySelector('.card-text').innerHTML = `<strong>Ingredients:</strong> ${recipe.ingredients}`;
                    clone.querySelectorAll('.card-text')[1].innerHTML = `<strong>Instructions:</strong> ${recipe.instructions}`;
                    clone.querySelector('.update-btn').setAttribute('data-id', recipe._id);
                    clone.querySelector('.update-btn').setAttribute('data-name', recipe.name);
                    clone.querySelector('.update-btn').setAttribute('data-ingredients', recipe.ingredients);
                    clone.querySelector('.update-btn').setAttribute('data-instructions', recipe.instructions);
                    clone.querySelector('.update-btn').setAttribute('data-image', recipe.image);
                    clone.querySelector('.delete-btn').setAttribute('data-id', recipe._id);
                    recipeList.append(clone);
                });
            },
            error: function() {
                alert('Error fetching recipes.');
            }
        });
    }

    // Handle update button click
    $(document).on('click', '.update-btn', function() {
        const id = $(this).data('_id');
        const name = $(this).data('name');
        const ingredients = $(this).data('ingredients');
        const instructions = $(this).data('instructions');
        const image = $(this).data('image');

        $('#updateId').val(id);
        $('#updateName').val(name);
        $('#updateIngredients').val(ingredients);
        $('#updateInstructions').val(instructions);
        $('#updatePreview').attr('src', `/uploads/${image}`).show();

        $('#updateModal').modal('show');
    });

    // Handle delete button click
    $(document).on('click', '.delete-btn', function() {
        const id = $(this).data('_id');
        $.ajax({
            url: `/recipes/${id}`,
            type: 'DELETE',
            success: function(response) {
                alert('Recipe deleted successfully!');
                fetchRecipes();
            },
            error: function() {
                alert('Error deleting recipe.');
            }
        });
    });



    // Initial fetch
    fetchRecipes();
});