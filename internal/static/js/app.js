document.getElementById('fetchData').addEventListener('click', fetchData);

document.getElementById('submitDataForm').addEventListener('submit', function(e) {
    e.preventDefault();
    submitData();
});

function fetchData() {
    fetch('/api/data')
        .then(response => response.json())
        .then(data => {
            document.getElementById('fetchResult').textContent = JSON.stringify(data, null, 2);
        })
        .catch(error => console.error('Error fetching data:', error));
}

function submitData() {
    const data = {
        value: document.getElementById('dataInput').value
    };

    fetch('/api/data', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(data),
    })
    .then(response => response.json())
    .then(data => {
        console.log('Success:', data);
        alert('Data submitted successfully');
        document.getElementById('submitDataForm').reset(); // Reset form
    })
    .catch((error) => {
        console.error('Error:', error);
    });
}
