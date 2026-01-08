import React, { useState } from 'react';
import ReactDOM from 'react-dom/client';

interface CounterProps {
    initialCount?: number;
}

function Counter({ initialCount = 0 }: CounterProps) {
    const [count, setCount] = useState(initialCount);

    return (
        <div style={{
            padding: '20px',
            border: '1px solid #ddd',
            borderRadius: '8px',
            maxWidth: '300px',
            textAlign: 'center'
        }}>
            <h2 style={{ marginBottom: '16px' }}>React Counter</h2>
            <p style={{ fontSize: '24px', fontWeight: 'bold', marginBottom: '16px' }}>
                Count: {count}
            </p>
            <div style={{ display: 'flex', gap: '10px', justifyContent: 'center' }}>
                <button
                    onClick={() => setCount(count - 1)}
                    style={{
                        padding: '8px 16px',
                        fontSize: '14px',
                        cursor: 'pointer',
                        backgroundColor: '#dc3545',
                        color: 'white',
                        border: 'none',
                        borderRadius: '4px'
                    }}
                >
                    Decrease
                </button>
                <button
                    onClick={() => setCount(0)}
                    style={{
                        padding: '8px 16px',
                        fontSize: '14px',
                        cursor: 'pointer',
                        backgroundColor: '#6c757d',
                        color: 'white',
                        border: 'none',
                        borderRadius: '4px'
                    }}
                >
                    Reset
                </button>
                <button
                    onClick={() => setCount(count + 1)}
                    style={{
                        padding: '8px 16px',
                        fontSize: '14px',
                        cursor: 'pointer',
                        backgroundColor: '#28a745',
                        color: 'white',
                        border: 'none',
                        borderRadius: '4px'
                    }}
                >
                    Increase
                </button>
            </div>
        </div>
    );
}

// Mount the React component to a DOM element
function mountReactComponent() {
    const container = document.getElementById('react-counter');
    if (container) {
        const root = ReactDOM.createRoot(container);
        root.render(<Counter initialCount={0} />);
    }
}

// Export for use in other modules
export { Counter, mountReactComponent };
