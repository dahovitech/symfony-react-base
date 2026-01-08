import './stimulus_bootstrap.ts';
/*
 * Welcome to your app's main JavaScript file!
 *
 * We recommend including the built version of this JavaScript file
 * (and its CSS file) in your base layout (base.html.twig).
 */

// any CSS you import will output into a single css file (app.css in this case)
import './styles/app.css';

// React components
import { mountReactComponent } from './react/Counter';

// Mount React components when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    mountReactComponent();
});
